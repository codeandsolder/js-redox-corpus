#!/usr/bin/env python3
from __future__ import annotations
import hashlib, importlib.util, json, os, sqlite3, subprocess, sys, tempfile
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
path=sys.argv[-1]; text=open(path,errors='replace').read(); fatal='INVALID_SENTINEL' in text; weak='WEAK_SENTINEL' in text; print(json.dumps({'schema':'js-sus-scan/v7','files':[{'input':path,'bytes':1,'diagnostics':int(fatal),'fatal_error':fatal,'signal_count':0 if fatal else (1 if weak else 5),'signal_kinds':{} if fatal else ({'base64_call_arg':1} if weak else {'eval':2}),'top_score':0 if fatal or weak else 17,'clusters':[] if fatal or weak else [{'score':17}],'actionable_signal_count':0 if fatal else (1 if weak else 3),'actionable_signal_kinds':{} if fatal else ({'base64_call_arg':1} if weak else {'dynamic_code_call':3}),'actionable_top_score':0 if fatal or weak else 15,'actionable_clusters':[] if fatal or weak else [{'score':15}]}]}))
"""); sus.chmod(0o755)
  sus_v8=w/'sus-v8'; sus_v8.write_text(sus.read_text().replace('js-sus-scan/v7','js-sus-scan/v8')); sus_v8.chmod(0o755)
  semantic=subprocess.run([sys.executable,str(SEMANTIC),'--database',str(db),'--candidate-dir',str(cand),'--sus-scan',str(sus_v8),'--chunk-size','1','--nice','0'],check=True,text=True,capture_output=True)
  sem_report=json.loads(semantic.stdout[semantic.stdout.index('{'):]); assert sem_report['newly_scanned']==3,sem_report; assert sem_report['current_actionable']==1,sem_report; assert sem_report['current_weak_signals']==1,sem_report; assert sem_report['current_invalid']==1,sem_report
  assert (cand/'semantic-actionable.txt').read_text().strip()==str(cap/body)
  assert (cand/'semantic-invalid.txt').read_text().strip()==str(cap/invalid_body)
  assert (cand/'semantic-weak-signals.txt').read_text().strip()==str(cap/weak_body)
  assert (cand/'quick-focus.txt').read_text().strip()==str(cap/body)
  semantic2=subprocess.run([sys.executable,str(SEMANTIC),'--database',str(db),'--candidate-dir',str(cand),'--sus-scan',str(sus_v8),'--chunk-size','1','--nice','0'],check=True,text=True,capture_output=True)
  assert 'semantic pending=0' in semantic2.stdout,semantic2.stdout
  # v7 -> v8 raw migration must rescan dynamic-code rows because literal
  # source is demoted to raw-only evidence in v8. Unrelated rows carry forward.
  raw_migration_db=w/'raw-migration.sqlite'; src=sqlite3.connect(db); raw_db=sqlite3.connect(raw_migration_db); src.backup(raw_db); src.close()
  raw_db.execute("INSERT OR REPLACE INTO body_semantic_scan SELECT sha256,'js-sus-scan/v7',scanned_at,diagnostics,fatal_error,raw_signal_count,raw_cluster_count,raw_top_score,raw_signal_kinds_json,actionable_signal_count,actionable_cluster_count,actionable_top_score,actionable_signal_kinds_json,decode_encoding,decode_source,decode_had_errors,decode_uncertain,parser_fatal_error,analysis_complete,parse_recovery,opaque_parse_spans_json FROM body_semantic_scan WHERE scan_contract='js-sus-scan/v8'")
  raw_db.execute("DELETE FROM body_semantic_scan WHERE scan_contract='js-sus-scan/v8'")
  raw_db.execute("UPDATE body_semantic_scan SET raw_signal_kinds_json=?, actionable_signal_kinds_json=? WHERE sha256=? AND scan_contract='js-sus-scan/v7'",('{}','{}',sha))
  dynamic_call=json.dumps({'dynamic_code_call':1},separators=(',',':'))
  raw_db.execute("UPDATE body_semantic_scan SET raw_signal_kinds_json=?, actionable_signal_kinds_json=? WHERE sha256=? AND scan_contract='js-sus-scan/v7'",(dynamic_call,dynamic_call,invalid_sha))
  dynamic_ctor=json.dumps({'dynamic_code_constructor':1},separators=(',',':'))
  raw_db.execute("UPDATE body_semantic_scan SET raw_signal_kinds_json=?, actionable_signal_kinds_json=? WHERE sha256=? AND scan_contract='js-sus-scan/v7'",(dynamic_ctor,dynamic_ctor,weak_sha))
  raw_db.commit()
  spec=importlib.util.spec_from_file_location('semantic_index',SEMANTIC); semantic_index=importlib.util.module_from_spec(spec); spec.loader.exec_module(semantic_index)
  assert semantic_index.migrate_previous_contract(raw_db)==1
  migrated_raw={r[0] for r in raw_db.execute("SELECT sha256 FROM body_semantic_scan WHERE scan_contract='js-sus-scan/v8'")}
  assert migrated_raw=={sha},migrated_raw
  raw_db.close()
  # v2 -> v4 bootstrapping may only clone rows whose result is unaffected by
  # newer scanner semantics / proof-gated transforms. Affected rows must run.
  migration_db=w/'migration.sqlite'; src=sqlite3.connect(db); dst=sqlite3.connect(migration_db); src.backup(dst); src.close()
  spec=importlib.util.spec_from_file_location('progress_updater',UPDATER); updater=importlib.util.module_from_spec(spec); spec.loader.exec_module(updater)
  updater.ensure_schema(dst)
  base={'analysis_contract':updater.PREVIOUS_ANALYSIS_CONTRACT,'pipeline_id':'old-pipeline','observed_at':'2026-01-01T00:00:00+00:00','output_sha256':None,'output_bytes':1,'deob_changed':0,'deob_iterations':1,'transform_total':0,'transforms_json':'{}','deob_error':None,'diagnostics':0,'fatal_error':0,'raw_signal_count':1,'raw_cluster_count':1,'raw_top_score':10,'raw_signal_kinds_json':'{}','actionable_signal_count':1,'actionable_cluster_count':1,'actionable_top_score':10,'parser_fatal_error':0,'analysis_complete':1,'parse_recovery':None,'opaque_parse_spans_json':'[]'}
  cases=[(sha,cap/body,{}),(invalid_sha,cap/invalid_body,{'direct_table_decoder':1}),(weak_sha,cap/weak_body,{'array_rotation':2,'rotation_checksum_iife':1})]
  with dst:
   for case_sha,case_path,kinds in cases:
    row=dict(base); row.update({'sha256':case_sha,'input_path':str(case_path),'actionable_signal_kinds_json':json.dumps(kinds,separators=(',',':')),'actionable_signal_count':sum(kinds.values()),'raw_signal_kinds_json':json.dumps(kinds,separators=(',',':')),'raw_signal_count':sum(kinds.values())})
    updater.write_row(dst,row)
  migrated=updater.migrate_previous_contract(dst,updater.ANALYSIS_CONTRACT,'current-pipeline')
  assert migrated==1,migrated
  migrated_shas={r[0] for r in dst.execute('SELECT sha256 FROM body_analysis_run WHERE analysis_contract=?',(updater.ANALYSIS_CONTRACT,))}
  assert migrated_shas=={sha},migrated_shas
  dst.close()
  for label,overrides in [
   ('deob-error',{'deob_error':'timeout'}),
   ('parser-incomplete',{'parser_fatal_error':1,'analysis_complete':0,'parse_recovery':'browser-legacy-call-assignment'}),
  ]:
   bad_db=w/f'migration-{label}.sqlite'; src=sqlite3.connect(db); bad=sqlite3.connect(bad_db); src.backup(bad); src.close(); updater.ensure_schema(bad)
   row=dict(base); row.update({'sha256':sha,'input_path':str(cap/body),'actionable_signal_kinds_json':'{}','actionable_signal_count':0,'raw_signal_kinds_json':'{}','raw_signal_count':0}); row.update(overrides)
   with bad: updater.write_row(bad,row)
   assert updater.migrate_previous_contract(bad,updater.ANALYSIS_CONTRACT,'current-pipeline')==0,label
   assert bad.execute('SELECT COUNT(*) FROM body_analysis_run WHERE analysis_contract=?',(updater.ANALYSIS_CONTRACT,)).fetchone()[0]==0,label
   bad.close()
  paths=w/'paths.txt'; paths.write_text(str(cap/body)+'\n')
  invalid_paths=w/'invalid-paths.txt'; invalid_paths.write_text(str(cap/invalid_body)+'\n')
  weak_paths=w/'weak-paths.txt'; weak_paths.write_text(str(cap/weak_body)+'\n')
  cp=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  report=json.loads(cp.stdout); assert report['recorded']==1,report; assert report['scheduled']==1,report; assert report['skipped_existing']==0,report; assert report['best_known']['residual']==1,report
  cp2=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  report2=json.loads(cp2.stdout); assert report2['requested']==1,report2; assert report2['scheduled']==0,report2; assert report2['skipped_existing']==1,report2; assert report2['recorded']==0,report2
  invalid_cp=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(invalid_paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  invalid_report=json.loads(invalid_cp.stdout); assert invalid_report['recorded']==1,invalid_report; assert invalid_report['best_known']['invalid']==1,invalid_report; assert invalid_report['best_known']['residual']==1,invalid_report
  weak_cp=subprocess.run([sys.executable,str(UPDATER),'--database',str(db),'--candidate-dir',str(cand),'--paths-file',str(weak_paths),'--deobfuscate-safe',str(deob),'--sus-scan',str(sus),'--pipeline-id','test-p1','--nice','0'],check=True,text=True,capture_output=True)
  weak_report=json.loads(weak_cp.stdout); assert weak_report['recorded']==1,weak_report; assert weak_report['best_known']['weak_signals']==1,weak_report; assert weak_report['best_known']['residual']==1,weak_report; assert weak_report['best_known']['invalid']==1,weak_report
  con=sqlite3.connect(db); row=con.execute('SELECT actionable_top_score,actionable_signal_count,transform_total FROM body_analysis_best WHERE sha256=?',(sha,)).fetchone(); assert row==(15,3,3),row; con.close()
  assert (cand/'known-invalid.txt').read_text().strip()==str(cap/invalid_body)
  assert (cand/'known-weak-signals.txt').read_text().strip()==str(cap/weak_body)
  assert (cand/'known-residual.txt').read_text().strip()==str(cap/body); assert (cand/'quick-focus.txt').read_text().strip()==str(cap/body)
  sample=subprocess.run([sys.executable,str(SAMPLER),'--database',str(db),'--sus-scan',str(sus),'--sample-per-stratum','1'],check=True,text=True,capture_output=True); sampled=json.loads(sample.stdout); assert sampled['schema']=='js-redox-corpus-classifier-sample/v2',sampled
  print('PASS: corpus progress records post-deob semantic residuals and refreshes focus candidates')
if __name__=='__main__': main()
