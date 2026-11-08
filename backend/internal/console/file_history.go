package console

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
)

// Two bounded passes preserve file order and exact totals without retaining an
// offset-sized buffer, creating a disk projection, or sharing foreground lanes.
func (a *App) fileHistory(ctx context.Context, params url.Values) (Object, error) {
	low, high, err := rangeParams(params, 60, now())
	if err != nil {
		return nil, err
	}
	if params.Get("all") == "1" {
		low = 0
	}
	limit, err := intParam(params, "limit", 100, 1, 500)
	if err != nil {
		return nil, err
	}
	offset, err := intParam(params, "offset", 0, 0, 2147483647)
	if err != nil {
		return nil, err
	}
	parts, args, err := eventFilter(params, true)
	if err != nil {
		return nil, err
	}
	parts = append([]string{"ts>=?", "ts<=?"}, parts...)
	args = append([]any{low * 1000, high * 1000}, args...)
	f, err := os.Open(a.Config.Stream)
	if err != nil {
		return nil, errors.New("历史事件流暂不可读")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("历史事件流类型无效")
	}
	size := info.Size()
	start := max(int64(0), size-(200<<20))
	if _, err = f.Seek(start, 0); err != nil {
		return nil, err
	}
	if start > 0 {
		reader := bufio.NewReader(f)
		for {
			line, e := reader.ReadSlice('\n')
			start += int64(len(line))
			if e == nil || e == io.EOF {
				break
			}
			if e != bufio.ErrBufferFull {
				return nil, e
			}
		}
	}
	db, err := sql.Open("aegis-sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, s := range []string{"PRAGMA temp_store=MEMORY", "PRAGMA max_page_count=4096", eventSchema()} {
		if _, err = db.ExecContext(ctx, s); err != nil {
			return nil, err
		}
	}
	names := columnNames()
	insertSQL := "INSERT INTO events (id," + strings.Join(names, ",") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(names)+1), ",") + ")"
	run := func(visit func([]*Prepared, []Object) error) error {
		if _, err := f.Seek(start, 0); err != nil {
			return err
		}
		reader := bufio.NewReaderSize(io.LimitReader(f, size-start), (1<<20)+2)
		batch := [][]byte{}
		process := func() error {
			if len(batch) == 0 {
				return nil
			}
			prepared, err := parallelMap(ctx, a.Pool, batch, ParseEvent)
			if err != nil {
				return err
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM events"); err != nil {
				tx.Rollback()
				return err
			}
			stmt, err := tx.PrepareContext(ctx, insertSQL)
			if err != nil {
				tx.Rollback()
				return err
			}
			for i, r := range prepared {
				if r == nil {
					continue
				}
				values := append([]any{i + 1}, r.Values...)
				if _, err = stmt.ExecContext(ctx, values...); err != nil {
					stmt.Close()
					tx.Rollback()
					return err
				}
			}
			stmt.Close()
			if err = tx.Commit(); err != nil {
				return err
			}
			matches, err := queryRows(ctx, db, "SELECT id FROM events WHERE "+strings.Join(parts, " AND ")+" ORDER BY id", args...)
			if err != nil {
				return err
			}
			if err = visit(prepared, matches); err != nil {
				return err
			}
			batch = nil
			return nil
		}
		discard := false
		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			line, e := reader.ReadSlice('\n')
			if e == io.EOF {
				break
			}
			if e == bufio.ErrBufferFull {
				discard = true
				continue
			}
			if e != nil {
				return e
			}
			if discard {
				discard = false
				continue
			}
			if len(line) > 1<<20 {
				continue
			}
			batch = append(batch, append([]byte(nil), line[:len(line)-1]...))
			if len(batch) >= 128 {
				if err := process(); err != nil {
					return err
				}
			}
		}
		return process()
	}
	total := int64(0)
	if err = run(func(_ []*Prepared, rows []Object) error { total += int64(len(rows)); return nil }); err != nil {
		return nil, err
	}
	events := []Object{}
	index := int64(0)
	first, last := max(int64(0), total-int64(offset+limit)), max(int64(0), total-int64(offset))
	if first < last {
		err = run(func(prepared []*Prepared, rows []Object) error {
			for _, row := range rows {
				if index >= first && index < last {
					r := prepared[int(integer(row["id"]))-1]
					value := clone(r.Record)
					delete(value, "_event_key")
					value["id"] = nil
					value["_raw"] = string(r.Raw)
					events = append(events, value)
				}
				index++
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	latest, err := f.Stat()
	if err != nil || !os.SameFile(info, latest) || latest.Size() < size {
		return nil, errors.New("历史事件流已切换，请重新查询")
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return Object{"total": total, "events": events, "query": params.Get("q"), "source": "file", "range": []float64{low, high}, "truncated": false, "scanned_bytes": size - start}, nil
}
