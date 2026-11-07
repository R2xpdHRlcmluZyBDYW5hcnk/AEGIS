"""Compare exact network summaries on a local copy or synthetic metadata, in milliseconds."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import sqlite3
import statistics
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import overview_metrics


def load(path):
    spec=importlib.util.spec_from_file_location('baseline_overview',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def seed(path, count):
    from event_processing import backend
    db=backend().EventDB(str(path))
    try:
        rows=((1700000000000+(i%count)*10,'flow' if i%8==7 else 'session',
               '192.0.2.1','198.51.100.1','http' if i%8>=3 else '', 'TCP',
               'a'*32+':'+format(i//8+1,'016x'), 400 if i%8==7 else None,
               800 if i%8==7 else None, i%8+1, i%8)
              for i in range(count))
        db.conn.executemany('INSERT INTO events(ts,type,src,dst,app,proto,session_id,'
            'bytes_toserver,bytes_toclient,pkts_toserver,pkts_toclient) VALUES(?,?,?,?,?,?,?,?,?,?,?)',rows)
        db.conn.commit()
    finally:db.conn.close()


def compare(path, before, repeats):
    conn=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        conn.execute('PRAGMA query_only=ON');conn.execute('PRAGMA cache_size=-2048')
        count,low,high=conn.execute('SELECT COUNT(*),MIN(ts),MAX(ts) FROM events').fetchone()
        if not count:raise ValueError('Empty input')
        samples={mode:{name:[] for name in ('before','after')} for mode in ('complete','progressive')}
        expected=None
        for repetition in range(repeats):
            order=(('before',before),('after',overview_metrics))
            if repetition%2:order=tuple(reversed(order))
            for mode in samples:
                for name,module in order:
                    cpu=time.process_time();wall=time.perf_counter()
                    result=module.summarize(conn,low/1000,high/1000,
                        publish_base=(lambda _:None) if mode=='progressive' else None)
                    wall_ms=(time.perf_counter()-wall)*1000;cpu_ms=(time.process_time()-cpu)*1000
                    result.pop('as_of',None)
                    if expected is None:expected=result
                    if result!=expected:raise AssertionError('Summary results changed')
                    samples[mode][name].append(dict(wall_ms=wall_ms,cpu_ms=cpu_ms))
        summary={}
        for mode,runs in samples.items():
            old=statistics.median(row['wall_ms'] for row in runs['before'])
            new=statistics.median(row['wall_ms'] for row in runs['after'])
            summary[mode]=dict(before_ms=round(old,3),after_ms=round(new,3),
                               reduction_percent=round((old-new)/old*100,2))
        return dict(records=count,connections=expected['flows'],span_seconds=round((high-low)/1000,3),
                    data_start_utc=datetime.fromtimestamp(low/1000,timezone.utc).isoformat(),
                    data_end_utc=datetime.fromtimestamp(high/1000,timezone.utc).isoformat(),
                    measured_at_utc=datetime.now(timezone.utc).isoformat(),
                    baseline_sha256=hashlib.sha256(Path(before.__file__).read_bytes()).hexdigest(),
                    current_sha256=hashlib.sha256(Path(overview_metrics.__file__).read_bytes()).hexdigest(),
                    repeats=repeats,equal=True,samples=samples,summary=summary)
    finally:conn.close()


def report(path, result, copied):
    rows=''.join('<tr><td>'+label+'</td>'+''.join('<td>'+str(result['summary'][mode][key])+'</td>'
        for key in ('before_ms','after_ms','reduction_percent'))+'</tr>'
        for mode,label in (('complete','完整统计'),('progressive','渐进统计')))
    source=html.escape(Path(__file__).read_text(encoding='utf-8'))
    output=html.escape(json.dumps(result,ensure_ascii=False,indent=2))
    path.write_text('''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>NDR 查询性能对照</title><style>body{font:16px/1.7 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 28px;color:#202a30;background:#f5f7f8}h1{font-size:30px}section{background:white;padding:24px;margin:20px 0;border:1px solid #ccd4d8;border-radius:10px}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #dce1e4;padding:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef2f4;padding:20px;font:13px/1.6 monospace}summary{cursor:pointer}small{color:#52616b}</style>
<h1>NDR 查询性能对照</h1><p>相同数据、相同范围，交错执行优化前后查询。逐次比较全部统计结果，忽略生成时间，结果完全一致。</p>
<section><h2>输入与方法</h2><p>数据：'''+('开发电脑上的日志副本重建库' if copied else '完全合成的会话元数据')+
f'''。记录 {result['records']} 条，连接 {result['connections']} 个，覆盖 {result['span_seconds']} 秒；每种路径重复 {result['repeats']} 次。
使用只读 SQLite 连接，页缓存预算 2 MiB；计时包含 SQL 执行与结果生成，以毫秒为单位。中位数保留三位小数，减少比例保留两位小数。</p>
<p>测量时间（UTC）：{result['measured_at_utc']}；数据时间（UTC）：{result['data_start_utc']} 至 {result['data_end_utc']}。前后实现的 SHA-256 与逐次结果见运行输出。</p>
<p>这测量开发电脑上的查询路径，不是路由器吞吐或完整 HTTP 响应时间。操作系统缓存未清空，结果不能代表冷盘延迟；数据副本可能包含已结束和仍活跃的会话。</p></section>
<section><h2>复现代码与运行输出</h2><p>本脚本位于 tests/benchmark_network_summary.py。运行示例：</p>
<pre>python -B tests/benchmark_network_summary.py --baseline /path/to/before-overview.py --source-db /path/to/local-copy.db --repeats 7 --html /path/to/report.html</pre>
<details><summary>完整可运行代码</summary><pre>'''+source+'''</pre></details><details><summary>逐次实际输出</summary><pre>'''+output+'''</pre></details></section>
<section><h2>结果</h2><table><thead><tr><th>查询路径</th><th>原中位数 ms</th><th>新中位数 ms</th><th>耗时减少 %</th></tr></thead><tbody>'''+rows+'''</tbody></table>
<p>优化将完整会话上的重复窗口聚合改为分组聚合；渐进统计复用连接代表记录计算端点，减少重复扫描和排序。基础计数仍先发布，字段口径与筛选不变。</p></section>
<small>实现与基准代码来自本项目；输入不含报文内容留存。报告不包含端点地址或原始日志。</small></html>''',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True,help='Trusted local prior overview_metrics.py')
    parser.add_argument('--source-db',type=Path,help='Development-computer database copy only')
    parser.add_argument('--rows',type=int,default=100000)
    parser.add_argument('--repeats',type=int,default=7)
    parser.add_argument('--html',type=Path)
    args=parser.parse_args()
    if args.rows<1 or not 1<=args.repeats<=30:parser.error('Positive rows and 1..30 repeats required')
    before=load(args.baseline)
    with tempfile.TemporaryDirectory(prefix='aegis-summary-benchmark-') as directory:
        path=args.source_db or Path(directory)/'synthetic.db'
        if args.source_db is None:seed(path,args.rows)
        result=compare(path,before,args.repeats)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if args.html:
        if args.html.resolve().is_relative_to(ROOT):parser.error('Export reports outside the source tree')
        report(args.html,result,args.source_db is not None)


if __name__=='__main__':main()
