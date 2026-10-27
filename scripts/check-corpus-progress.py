#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, sqlite3, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; BUILDER=ROOT/'scripts/build-corpus-catalog.py'; SEMANTIC=ROOT/'scripts/build-corpus-semantic-index.py'; UPDATER=ROOT/'scripts/update-corpus-progress.py'; SAMPLER=ROOT/'scripts/check-corpus-classifier-sample.py'
def main():
 with tempfile.TemporaryDirectory(prefix='js-redox-progress-test-') as tmp:
  w=Path(tmp); captures=w/'captures'; cap=captures/'0001-popunder-ads-test'; (cap/'resources').mkdir(parents=True); (cap/'runtime-scripts').mkdir(); (cap/'recorder-manifest.json').write_text('{}\n')
  raw=b"while(true){switch(x){case 1:eval('x');break;}}"; sha=hashlib.sha256(raw).hexdigest(); body='resources/a.js'; (cap/body).write_bytes(raw)
  invalid=b"INVALID_SENTINEL ("; invalid_sha=hashlib.sha256(invalid).hexdigest(); invalid_body='resources/b.js'; (cap/invalid_body).write_bytes(invalid)
  weak=b"WEAK_SENTINEL"; weak_sha=hashlib.sha256(weak).hexdigest(); weak_body='resources/c.js'; (cap/weak_body).write_bytes(weak)
  (cap/'network.json').write_text(json.dumps([
   {'url':'https://x.example/a.js','resourceType':'Script','mimeType':'application/javascript','body':{'sha256':sha,'path':body,'size':len(raw)}},
   {'url':'https://x.example/b.js','resourceType':'Script','mimeType':'application/javascript','body':{'sha256':invalid_sha,'path':invalid_body,'size':len(invalid)}},
   {'url':'https://x.example/c.js','resourceType':'Script','mimeType':'application/javascript','body':{'sha256':weak_sha,'path':weak_body,'size':len(weak)}},
  ])); (cap/'runtime-scripts.json').write_text('[]')
  db=w/'catalog.sqlite'; cand=w/'candidates'; summary=w/'summary.json'
  subprocess.run([sys.executable,str(BUILDER),'--captures',str(captures),'--database',str(db),'--candidate-dir',str(cand),'--summary',str(summary),'--jobs','1'],check=True,stdout=subprocess.PIPE,text=True)
  deob=w/'deob'; deob.write_text("""#!/usr/bin/env python3
import hashlib,json,shutil,sys
from pathlib import Path
a=sys.argv[1:]; inp=Path(a[0]); out=Path(a[1]); report=Path(a[a.index('--report')+1]); shutil.copyfile(inp,out); raw=inp.read_bytes(); sha=hashlib.sha256(raw).hexdigest(); report.write_text(json.dumps({'schema':'js-safe-deobfuscate/v1','input_sha256':sha,'output_sha256':sha,'changed':True,'iterations':2,'transforms':{'constant_fold':3}}))
"""); deob.chmod(0o755)
  sus=w/'sus'; sus.write_text("""#!/usr/bin/env python3
import json,sys
path=sys.argv[-1]; text=open(path,errors='replace').read(); fatal='INVALID_SENTINEL' in text; weak='WEAK_SENTINEL' in text; print(json.dumps({'schema':'js-sus-scan/v6','files':[{'input':path,'bytes':1,'diagnostics':int(fatal),'fatal_error':fatal,'signal_count':0 if fatal else (1 if weak else 5),'signal_kinds':{} if fatal else ({'base64_call_arg':1} if weak else {'eval':2}),'top_score':0 if fatal or weak else 17,'clusters':[] if fatal or weak else [{'score':17}],'actionable_signal_count':0 if fatal else (1 if weak else 3),'actionable_signal_kinds':{} if fatal else ({'base64_call_arg':1} if weak else {'dynamic_code_call':3}),'actionable_top_score':0 if fatal or weak else 15,'actionable_clusters':[] if fatal or weak else [{'score':15}]}]}))
"""); sus.chmod(0o755)
  post_sus=w/'post-sus'; post_sus.write_text(sus.read_text().replace('js-sus-scan/v6','js-sus-scan/v5')); post_sus.chmod(0o755)
  semantic=subprocess.run([sys.executable,str(SEMANTIC),'--database',str(db),'--candidate-dir',str(cand),'--sus-scan',str(sus),'--chunk-size','1','--nice','0'],check=True,text=True,capture_output=True)
  sem_report=json.loads(semantic.stdout[semantic.stdout.index('{'):]); assert sem_report['newly_scanned']==3,sem_report; assert sem_report['current_actionable']==1,sem_report; assert sem_report['current_weak_signals']==1,sem_report; assert sem_report['current_invalid']==1,sem_report
  assert (cand/'semantic-actionable.txt').read_text().strip()==str(cap/body)
  assert (cand/'semantic-invalid.txt').read_text().strip()==str(cap/invalid_body)
  assert (cand/'semantic-weak-signals.txt').read_text().strip()==str(cap/weak_body)
  assert (cand/'quick-focus.txt').read_text().strip()==str(cap/body)
  semantic2=subprocess.run([sys.executable,str(SEMANTIC),'--database',str(db),'--candidate-dir',str(cand),'--sus-scan',str(sus),'--chunk-size','1','--nice','0'],check=True,text=True,capture_output=True)
  assert 'semantic pending=0' in semantic2.stdout,semantic2.stdout
  paths=w/'paths.txt'; paths.write_text(str(cap/body)+'\n')
  invalid_paths=w/'invalid-paths.txt'; invalid_paths.write_text(str(cap/invalid_body)+'\n')
  weak_paths=w/'weak-paths.txt'; weak_paths.write_text(str(cap/weak_body)+'\n')
  cp=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(post_sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  report=json.loads(cp.stdout); assert report['recorded']==1,report; assert report['scheduled']==1,report; assert report['skipped_existing']==0,report; assert report['best_known']['residual']==1,report
  cp2=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(post_sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  report2=json.loads(cp2.stdout); assert report2['requested']==1,report2; assert report2['scheduled']==0,report2; assert report2['skipped_existing']==1,report2; assert report2['recorded']==0,report2
  invalid_cp=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(invalid_paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(post_sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  invalid_report=json.loads(invalid_cp.stdout); assert invalid_report['recorded']==1,invalid_report; assert invalid_report['best_known']['invalid']==1,invalid_report; assert invalid_report['best_known']['residual']==1,invalid_report
  weak_cp=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(weak_paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(post_sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  weak_report=json.loads(weak_cp.stdout); assert weak_report['recorded']==1,weak_report; assert weak_report['best_known']['weak_signals']==1,weak_report; assert weak_report['best_known']['residual']==1,weak_report; assert weak_report['best_known']['invalid']==1,weak_report
  con=sqlite3.connect(db); row=con.execute('SELECT actionable_top_score,actionable_signal_count,transform_total FROM body_analysis_best WHERE sha256=?',(sha,)).fetchone(); assert row==(15,3,3),row; con.close()
  assert (cand/'known-invalid.txt').read_text().strip()==str(cap/invalid_body)
  assert (cand/'known-weak-signals.txt').read_text().strip()==str(cap/weak_body)
  assert (cand/'known-residual.txt').read_text().strip()==str(cap/body); assert (cand/'quick-focus.txt').read_text().strip()==str(cap/body)
  sample=subprocess.run([sys.executable,str(SAMPLER),'--database',str(db),'--sus-scan',str(sus),'--sample-per-stratum','1'],check=True,text=True,capture_output=True); sampled=json.loads(sample.stdout); assert sampled['schema']=='js-redox-corpus-classifier-sample/v2',sampled
  print('PASS: corpus progress records post-deob semantic residuals and refreshes focus candidates')
if __name__=='__main__': main()
