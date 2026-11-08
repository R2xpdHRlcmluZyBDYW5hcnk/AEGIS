package console

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
)

type overviewParallelKey struct{}

type residentImage struct {
	path                string
	version, generation uint64
	bounds              [2]float64
	count               int64
	refs                int
}

// systemd owns this private directory. Only tmpfs is accepted for production
// snapshots; neither the event database nor /tmp is used as a scratch store.
func overviewRuntimeDirectory() string {
	for _, dir := range strings.Split(os.Getenv("RUNTIME_DIRECTORY"), ":") {
		if dir != "/run/ips-web-overview" {
			continue
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			continue
		}
		var fs syscall.Statfs_t
		if syscall.Statfs(dir, &fs) == nil && uint64(fs.Type) == 0x01021994 {
			return dir
		}
	}
	return ""
}

func (r *RecentEvents) releaseImage(image *residentImage) {
	image.refs--
	if image.refs == 0 {
		os.Remove(image.path)
	}
}

// r.mu is held only while copying pages. The completed image is never written
// again, allowing independent private SQLite readers and continued ingestion.
func (r *RecentEvents) imageLocked(ctx context.Context) (*residentImage, error) {
	version := r.Version.Load()
	if r.image != nil && r.image.version == version && r.image.generation == r.generation {
		return r.image, nil
	}
	if r.image != nil {
		r.releaseImage(r.image)
		r.image = nil
	}
	f, err := os.CreateTemp(r.app.Config.snapshotDir, "overview-*.db")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	f.Close()
	keep := false
	defer func() {
		if !keep {
			os.Remove(path)
		}
	}()
	destination, err := sql.Open("aegis-sqlite", "file:"+filepath.ToSlash(path)+"?cache=private&_journal_mode=OFF&_synchronous=OFF&_cache_size=-512")
	if err != nil {
		return nil, err
	}
	destination.SetMaxOpenConns(1)
	dest, err := destination.Conn(ctx)
	if err == nil {
		err = r.anchor.Raw(func(source any) error {
			return dest.Raw(func(target any) error {
				backup, err := target.(*sqlite.SQLiteConn).Backup("main", source.(*sqlite.SQLiteConn), "main")
				if err != nil {
					return err
				}
				var failure error
				remaining, stalled := -1, 0
				for ctx.Err() == nil {
					done, e := backup.Step(256)
					if e != nil {
						failure = e
						break
					}
					if done {
						break
					}
					if backup.Remaining() == remaining {
						stalled++
					} else {
						stalled = 0
					}
					remaining = backup.Remaining()
					if stalled >= 3 {
						failure = errors.New("内存快照复制未推进")
						break
					}
				}
				if ctx.Err() != nil {
					failure = ctx.Err()
				}
				if e := backup.Finish(); failure == nil {
					failure = e
				}
				return failure
			})
		})
		dest.Close()
	}
	if e := destination.Close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > r.app.Config.PreloadBytes {
		return nil, errors.New("内存快照超过事件池预算")
	}
	if err = os.Chmod(path, 0400); err != nil {
		return nil, err
	}
	lo, hi := r.Bounds()
	image := &residentImage{path: path, version: version, generation: r.generation, bounds: [2]float64{lo, hi}, count: r.Count(), refs: 1}
	r.image = image
	keep = true
	return image, nil
}

func (r *RecentEvents) frozenSnapshot(ctx context.Context, low, high float64, overview bool) (*Snapshot, func(), bool, error) {
	if !r.Ready() || !r.mu.TryLock() {
		return nil, nil, false, nil
	}
	lo, hi := r.Bounds()
	if r.generation != r.app.Store.Generation.Load() || (!overview && (low < lo || high > hi)) {
		r.mu.Unlock()
		return nil, nil, false, nil
	}
	image, err := r.imageLocked(ctx)
	if err != nil {
		r.mu.Unlock()
		return nil, nil, false, err
	}
	image.refs++
	r.mu.Unlock()
	reserved, releaseHelpers := reserveSQLHelpers()
	address := (&url.URL{Scheme: "file", Path: filepath.ToSlash(image.path)}).String() + "?mode=ro&immutable=1&cache=private&_query_only=1&_cache_size=-2048"
	db, err := sql.Open("aegis-recent-sqlite", address)
	g := &Snapshot{ctx: ctx, recent: true, bounds: image.bounds, count: image.count}
	g.release = func() {
		if db != nil {
			db.Close()
		}
		releaseHelpers()
		r.mu.Lock()
		r.releaseImage(image)
		r.mu.Unlock()
	}
	if err == nil {
		db.SetMaxOpenConns(reserved + 1)
		db.SetMaxIdleConns(reserved + 1)
		for i := 0; i <= reserved; i++ {
			var conn *sql.Conn
			conn, err = db.Conn(ctx)
			if err != nil {
				break
			}
			g.connections = append(g.connections, conn)
			var tx *sql.Tx
			tx, err = conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				break
			}
			if i == 0 {
				g.main = &queryTransaction{Tx: tx}
			} else {
				g.helpers = append(g.helpers, &queryTransaction{Tx: tx})
			}
		}
	}
	if err != nil {
		g.Close()
		return nil, nil, false, err
	}
	return g, g.Close, true, nil
}

func (r *RecentEvents) waitFrozenSnapshot(ctx context.Context) (*Snapshot, func(), error) {
	for {
		g, release, ok, err := r.frozenSnapshot(ctx, 0, 0, true)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			return g, release, nil
		}
		if message := r.Error(); message != "" {
			return nil, nil, errors.New(message)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
}
