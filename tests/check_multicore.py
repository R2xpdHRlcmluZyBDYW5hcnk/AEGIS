"""Local synthetic, serial/parallel equivalence and worker-reuse measurements.

Never run this on the detection device. All data and databases use local temp.
"""
import argparse
from contextlib import closing
import hashlib
import html
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import platform
import sys
import tempfile
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from parallel_cpu import CPUExecutor,byte_batches
from parallel_sql import ReadExecutor
from event_processing import backend,projection_rows
from rule_inventory import parse_parallel


def digest_rows(rows):
    digest=hashlib.sha256()
    for row in rows:digest.update(repr(row).encode('utf-8')+b'\n')
    return digest.hexdigest()


def load_bridge():
    loader=importlib.machinery.SourceFileLoader('bridge_benchmark',str(ROOT/'ips-event-bridge'))
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader))
    loader.exec_module(module)
    return module


def bridge_run(module,root,logs,instance,pool,label):
    output=root/(label+'.json');state=root/(label+'.state')
    bridge=module.Bridge(logs,output,state,instance);bridge.cpu=pool
    pids=set();records=0;start=time.perf_counter()
    while True:
        count=bridge.poll();records+=count;pids.update(bridge.worker_pids)
        if not count:break
    seconds=time.perf_counter()-start
    with output.open('rb') as stream:checksum=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(seconds=seconds,sha256=checksum,records=records,processes=len(pids) or 1),output


def ingest_run(module,root,stream,pool,label):
    db=module.EventDB(str(root/(label+'.db')))
    try:
        store=module.EventStore(str(stream),initial_tail=stream.stat().st_size+1)
        store.db,store.cpu=db,pool;pids=set();start=time.perf_counter()
        while store.offset<stream.stat().st_size:
            store.last_ingest=0;store.ingest(budget=1);pids.update(store.worker_pids)
        db.flush();seconds=time.perf_counter()-start
        cursor=db.conn.execute('SELECT '+','.join(db.names)+' FROM events ORDER BY id')
        checksum=digest_rows(cursor)
        count=db.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        return dict(seconds=seconds,sha256=checksum,records=count,processes=len(pids) or 1)
    finally:db.conn.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records',type=int,default=32768)
    parser.add_argument('--html',type=Path)
    args=parser.parse_args()
    if not 4096<=args.records<=200000:parser.error('Use 4096..200000 synthetic records')
    if args.html and args.html.resolve().is_relative_to(ROOT):parser.error('Export reports outside the source tree')
    module=backend();bridge_module=load_bridge();measurements=[]
    with tempfile.TemporaryDirectory(prefix='ips-multicore-check-') as directory:
        root=Path(directory);logs=root/'native';logs.mkdir();source=logs/'0_file_connector_ndr_transmit'
        instance=root/'instance.json';instance.write_text('{"epoch":"fixture","started":0}')
        with source.open('w') as output:
            for i in range(args.records):
                output.write(json.dumps(dict(ts=1700000000+i/1000,uid=2**63+i,trans_id=i,
                    query=str(i)+'.'+'x'*400+'.example.test',proto='UDP',
                    **{'id.orig_h':'192.0.2.1','id.orig_p':12345,'id.resp_h':'198.51.100.1','id.resp_p':53}))+'\n')
        text=''.join('alert tcp any any -> any any (msg:"fixture %d %s"; sid:%d; rev:1;)\n'%(i,'x'*240,1000+i) for i in range(args.records)).encode()
        projection=[(i,1700000000000+i,'flow',str(i),28333333,'192.0.2.1','198.51.100.1',
                     'tls','TCP','','',100,1,0,'',12345,443) for i in range(args.records)]
        for workers in (1,4):
            with closing(CPUExecutor(workers)) as pool:
                for reuse in (False,True):
                    label=str(workers)+'-'+str(int(reuse))
                    result,stream=bridge_run(bridge_module,root,logs,instance,pool,'bridge-'+label)
                    measurements.append(dict(task='bridge',workers=pool.workers,reused=reuse,**result))
                    stats={};started=time.perf_counter();rows=parse_parallel(text,pool,stats)
                    elapsed=time.perf_counter()-started
                    measurements.append(dict(task='catalog',workers=pool.workers,reused=reuse,
                        seconds=elapsed,sha256=digest_rows(rows),records=len(rows),processes=len(stats.get('pids',())) or 1))
                    result=ingest_run(module,root,stream,pool,'ingest-'+label)
                    measurements.append(dict(task='ingest',workers=pool.workers,reused=reuse,**result))
                    stats={};started=time.perf_counter()
                    rows=[row for chunk in pool.ordered(projection_rows,byte_batches(projection,size=lambda _:1024),stats) for row in chunk]
                    elapsed=time.perf_counter()-started
                    measurements.append(dict(task='backfill',workers=pool.workers,reused=reuse,
                        seconds=elapsed,sha256=digest_rows(rows),records=len(rows),processes=len(stats.get('pids',())) or 1))
        db=module.EventDB(str(root/'queries.db'))
        try:
            for i in range(args.records):
                rec=dict(ts=1700000000+i/1000,type='alert' if i%4 else 'drop',sev=i%3+1,
                    sig='fixture '+str(i%200),sig_id=1000+i%200,src='192.0.2.'+str(i%64+1),
                    dst='198.51.100.'+str(i%64+1),sport=12345,dport=443,proto='TCP',
                    app='tls',action='blocked' if i%4==0 else 'allowed')
                db.add(rec,json.dumps(rec))
            db.flush()
            for helpers in (0,3):
                app=SimpleNamespace(db=db,config={'read_workers':4})
                service=module.DataService(app,module.SharedCache(1<<20));service.sql.close()
                service.sql=ReadExecutor(helpers);db.query_pool=service.sql
                try:
                    for reuse in (False,True):
                        def read(reader):
                            result=reader.db.security_summary(start=1699999999,end=1700010000,dedup=True)
                            return result,len(reader.db.parallel.members)+1
                        started=time.perf_counter();result,threads=service.execute(read)
                        elapsed=time.perf_counter()-started
                        measurements.append(dict(task='summary',workers=helpers+1,reused=reuse,
                            seconds=elapsed,sha256=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest(),
                            records=result['total'],threads=threads))
                finally:service.close()
        finally:db.conn.close()
    tasks=sorted({row['task'] for row in measurements})
    for task in tasks:
        records=[row for row in measurements if row['task']==task]
        if len({row['sha256'] for row in records})!=1:raise AssertionError('Serial/parallel output differs: '+task)
    ratios={}
    for task in tasks:
        rows={row['workers']:row for row in measurements if row['task']==task and row['reused']}
        ratios[task]=rows[1]['seconds']/rows[4]['seconds'] if 4 in rows else None
    result=dict(python=platform.python_version(),platform=platform.system(),synthetic_records=args.records,
                measurements=measurements,reused_speed_ratio=ratios,all_outputs_equal=True)
    print(json.dumps(result,indent=2),flush=True)
    if args.html:
        labels={'bridge':'数据桥','catalog':'规则目录','ingest':'解析与入库','backfill':'历史投影转换','summary':'概览 SQL 聚合'}
        table=''.join('<tr><td>%s</td><td>%d</td><td>%s</td><td>%.6f s</td><td>%s</td></tr>'%(
            labels[row['task']],row['workers'],'复用工作池' if row['reused'] else '首次调用',row['seconds'],
            row.get('processes',row.get('threads'))) for row in measurements)
        document='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>多核处理验证</title><style>body{font:16px/1.7 system-ui,"Microsoft YaHei",sans-serif;max-width:1080px;margin:32px auto;padding:20px;color:#172332}h1{font-size:30px}h2{margin-top:32px}table{width:100%;border-collapse:collapse}td,th{padding:10px;text-align:left;border-bottom:1px solid #ccd4dd}.scroll{overflow:auto}pre{background:#152334;color:#eff4fa;padding:18px;border-radius:8px;overflow:auto;font:12px/1.5 monospace}summary{cursor:pointer}aside{background:#edf5ef;border-left:4px solid #42764f;padding:14px}@media(max-width:650px){body{margin:0;padding:16px}h1{font-size:25px}}</style><h1>多核处理验证</h1><aside>同一实现的单工作单元和四工作单元对照。全部合成输入、数据库及输出位于开发电脑系统临时目录；未在路由器上运行数据测试。</aside><h2>可运行代码</h2><p>从项目根目录运行 <code>python -B tests/check_multicore.py --html &lt;源码目录外的报告路径&gt;</code>。</p><details><summary>完整 Python 脚本</summary><pre>__CODE__</pre></details><h2>运行过程与完整输出</h2><p>先生成固定结构的合成数据，分别以单进程及最多四进程处理数据桥、目录、入库和历史投影，随后对照单连接与四连接概览聚合。每组再使用原工作池运行一次。计时不包含数据生成与输出摘要；数据桥首次调用包含进程启动。未清空操作系统页缓存，工作池复用数值不代表首次打开页面，也不代表设备耗时。</p><details><summary>原始测量结果</summary><pre>__RESULT__</pre></details><h2>测量值</h2><div class="scroll"><table><thead><tr><th>任务</th><th>工作单元上限</th><th>调用</th><th>耗时</th><th>实际进程或线程</th></tr></thead><tbody>__ROWS__</tbody></table></div><h2>结果与限制</h2><p>每项任务的完整输出 SHA-256 在单工作单元、多工作单元及复用调用之间一致。比率由脚本计算，数值大于 1 表示本次复用测量中并行更快，小于 1 表示并行开销超过收益。进程数和线程数证明工作任务发生并发，不承诺核心平均占用或所有任务提速。</p><p>数据库提交、检查点推进、规则冲突合并和最终文件替换保持有序。Snort 引擎实现及检测进程的配置不属于此次计算改造范围。</p></html>'''
        document=document.replace('__CODE__',html.escape(Path(__file__).read_text())).replace('__RESULT__',html.escape(json.dumps(result,indent=2))).replace('__ROWS__',table)
        args.html.parent.mkdir(parents=True,exist_ok=True);args.html.write_text(document,encoding='utf-8')
        print(args.html,flush=True)


if __name__=='__main__':main()
