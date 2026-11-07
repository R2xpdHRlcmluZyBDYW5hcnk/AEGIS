"""Replay a bounded local event-stream copy; compare durable writes and read results."""
import argparse
import json
from pathlib import Path
import statistics
import struct
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from event_processing import backend,parse_events


def compare(data):
    records=parse_events(([(line,i) for i,line in enumerate(data.split(b'\n')[:-1]) if line.strip()],True))
    if not records:raise ValueError('The sample has no complete supported events')
    module=backend();outcomes=[];expected=None;high=max(row[0]['ts'] for row in records)+1
    with tempfile.TemporaryDirectory(prefix='aegis-wal-benchmark-') as temporary:
        for trial,threshold in enumerate((1000,4096,4096,1000,1000,4096)):
            path=Path(temporary)/(str(trial)+'.db')
            db=module.EventDB(str(path));db.conn.execute('PRAGMA wal_autocheckpoint='+str(threshold))
            generations=set();peak=0
            def observe():
                wal=Path(str(path)+'-wal')
                with wal.open('rb') as handle:head=handle.read(32)
                if len(head)==32:generations.add(struct.unpack('>I',head[12:16])[0])
                return wal.stat().st_size
            try:
                started=time.perf_counter()
                for index,(_,_,values) in enumerate(records):
                    db.add_prepared(values)
                    if index%db.BATCH==db.BATCH-1:peak=max(peak,observe())
                db.flush();elapsed=time.perf_counter()-started;peak=max(peak,observe())
                if db.write_error:raise RuntimeError(db.write_error)
                rows=db.conn.execute('SELECT * FROM events ORDER BY id').fetchall()
                if expected is None:expected=rows
                else:assert rows==expected,'Checkpoint policy changed stored evidence'
                started=time.perf_counter()
                total,page=db.search_range(0,high,limit=50,list_view=True)
                query_ms=(time.perf_counter()-started)*1000
                assert total==len(rows) and len(page)==min(50,len(rows))
                started=time.perf_counter()
                busy,frames,written=db.conn.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()
                elapsed+=time.perf_counter()-started
                assert not busy and frames==written,'Include the complete checkpoint cost'
                outcomes.append(dict(threshold=threshold,seconds=elapsed,restarts=len(generations)-1,
                                     peak=peak,query_ms=query_ms))
            finally:db.conn.close()
    return [dict(threshold_pages=threshold,rows=len(expected),
                 median_seconds=round(statistics.median(row['seconds'] for row in outcomes if row['threshold']==threshold),4),
                 median_wal_restarts=statistics.median(row['restarts'] for row in outcomes if row['threshold']==threshold),
                 max_wal_bytes=max(row['peak'] for row in outcomes if row['threshold']==threshold),
                 median_query_ms=round(statistics.median(row['query_ms'] for row in outcomes if row['threshold']==threshold),3))
            for threshold in (1000,4096)]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path,help='Event-stream copy in the development computer system temp directory')
    args=parser.parse_args();path=args.input.resolve()
    if not path.is_relative_to(Path(tempfile.gettempdir()).resolve()) or path.is_relative_to(ROOT):
        parser.error('Copy source data to this computer system temporary directory first')
    with path.open('rb') as handle:data=handle.read(4<<20)
    print(json.dumps(compare(data),indent=2))
    print('Six trials produced identical database rows. Local timings do not predict router throughput.')
