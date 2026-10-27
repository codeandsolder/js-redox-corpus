#!/usr/bin/env python3
"""Run safe deobfuscation + semantic suspiciousness scan and persist per-body progress."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, importlib.util, json, os, sqlite3, subprocess, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from corpus_env import CORPUS_ROOT, JS_REDOX_ROOT, REPO_ROOT
ROOT=REPO_ROOT
DEFAULT_CORPUS=CORPUS_ROOT; DEFAULT_DB=DEFAULT_CORPUS/'preclass/corpus.sqlite'; DEFAULT_CANDIDATES=DEFAULT_CORPUS/'preclass/candidates'
DEFAULT_DEOB=JS_REDOX_ROOT/'.cargo-target-nodebug/release/deobfuscate-safe'; DEFAULT_SUS=JS_REDOX_ROOT/'.cargo-target-nodebug/release/sus-scan'; ANALYSIS_CONTRACT='safe-deob+sus/v2'; PREVIOUS_ANALYSIS_CONTRACT='safe-deob+sus/v1'; SUS_CONTRACT='js-sus-scan/v4'
POST_CANDIDATE_NAMES=('known-invalid','known-residual','known-weak-signals','known-zero','untested-interesting','quick-focus','regressed-from-best','llm-review-zero')
def sha256_file(path):
 d=hashlib.sha256();
 with path.open('rb') as h:
  for chunk in iter(lambda:h.read(1024*1024),b''): d.update(chunk)
 return d.hexdigest()
def utc_now(): return dt.datetime.now(dt.UTC).isoformat(timespec='microseconds')
def ensure_schema(db):
 db.executescript("""
 CREATE TABLE IF NOT EXISTS body_analysis_run(sha256 TEXT NOT NULL,analysis_contract TEXT NOT NULL,pipeline_id TEXT NOT NULL,observed_at TEXT NOT NULL,input_path TEXT NOT NULL,output_sha256 TEXT,output_bytes INTEGER,deob_changed INTEGER NOT NULL,deob_iterations INTEGER,transform_total INTEGER NOT NULL,transforms_json TEXT NOT NULL,deob_error TEXT,diagnostics INTEGER NOT NULL,fatal_error INTEGER NOT NULL,raw_signal_count INTEGER NOT NULL,raw_cluster_count INTEGER NOT NULL,raw_top_score INTEGER NOT NULL,raw_signal_kinds_json TEXT NOT NULL,actionable_signal_count INTEGER NOT NULL,actionable_cluster_count INTEGER NOT NULL,actionable_top_score INTEGER NOT NULL,actionable_signal_kinds_json TEXT NOT NULL,PRIMARY KEY(sha256,analysis_contract,pipeline_id));
 CREATE INDEX IF NOT EXISTS analysis_contract_idx ON body_analysis_run(analysis_contract,sha256);
 CREATE INDEX IF NOT EXISTS analysis_residual_idx ON body_analysis_run(analysis_contract,fatal_error,actionable_top_score,actionable_signal_count);
 DROP VIEW IF EXISTS body_analysis_best;
 CREATE VIEW body_analysis_best AS SELECT * FROM (SELECT r.*,ROW_NUMBER() OVER(PARTITION BY sha256,analysis_contract ORDER BY fatal_error ASC,actionable_top_score ASC,actionable_signal_count ASC,actionable_cluster_count ASC,diagnostics ASC,transform_total DESC,observed_at DESC,pipeline_id DESC) AS _rank FROM body_analysis_run r) WHERE _rank=1;
 DROP VIEW IF EXISTS body_analysis_latest;
 CREATE VIEW body_analysis_latest AS SELECT * FROM (SELECT r.*,ROW_NUMBER() OVER(PARTITION BY sha256,analysis_contract ORDER BY observed_at DESC,pipeline_id DESC) AS _rank FROM body_analysis_run r) WHERE _rank=1;
 """)
 columns={r[1] for r in db.execute('PRAGMA table_info(body_analysis_run)')}
 additions={'parser_fatal_error':'INTEGER NOT NULL DEFAULT 0','analysis_complete':'INTEGER NOT NULL DEFAULT 1','parse_recovery':'TEXT','opaque_parse_spans_json':"TEXT NOT NULL DEFAULT '[]'"}
 for name,declaration in additions.items():
  if name not in columns: db.execute(f'ALTER TABLE body_analysis_run ADD COLUMN {name} {declaration}')
 # Views created before ALTER expand SELECT * at query time in SQLite, but
 # recreate them so their stored SQL/provenance matches the current schema.
 db.executescript("""
 DROP VIEW IF EXISTS body_analysis_best;
 CREATE VIEW body_analysis_best AS SELECT * FROM (SELECT r.*,ROW_NUMBER() OVER(PARTITION BY sha256,analysis_contract ORDER BY fatal_error ASC,actionable_top_score ASC,actionable_signal_count ASC,actionable_cluster_count ASC,diagnostics ASC,transform_total DESC,observed_at DESC,pipeline_id DESC) AS _rank FROM body_analysis_run r) WHERE _rank=1;
 DROP VIEW IF EXISTS body_analysis_latest;
 CREATE VIEW body_analysis_latest AS SELECT * FROM (SELECT r.*,ROW_NUMBER() OVER(PARTITION BY sha256,analysis_contract ORDER BY observed_at DESC,pipeline_id DESC) AS _rank FROM body_analysis_run r) WHERE _rank=1;
 """)

def migrate_previous_contract(db,contract,pipe):
 if contract!=ANALYSIS_CONTRACT:return 0
 # Contract migration is a one-time bootstrap. Once any v2 rows exist,
 # subsequent engine/tool commits must create fresh analysis rows only for the
 # explicitly scheduled inputs rather than cloning the entire v1 ledger again.
 if db.execute('SELECT 1 FROM body_analysis_run WHERE analysis_contract=? LIMIT 1',(contract,)).fetchone(): return 0
 before=db.total_changes
 with db:
  db.execute("""
  INSERT OR IGNORE INTO body_analysis_run(
   sha256,analysis_contract,pipeline_id,observed_at,input_path,output_sha256,output_bytes,
   deob_changed,deob_iterations,transform_total,transforms_json,deob_error,diagnostics,fatal_error,
   raw_signal_count,raw_cluster_count,raw_top_score,raw_signal_kinds_json,actionable_signal_count,
   actionable_cluster_count,actionable_top_score,actionable_signal_kinds_json,
   parser_fatal_error,analysis_complete,parse_recovery,opaque_parse_spans_json)
  SELECT sha256,?, ?,observed_at,input_path,output_sha256,output_bytes,
   deob_changed,deob_iterations,transform_total,transforms_json,deob_error,diagnostics,fatal_error,
   raw_signal_count,raw_cluster_count,raw_top_score,raw_signal_kinds_json,actionable_signal_count,
   actionable_cluster_count,actionable_top_score,actionable_signal_kinds_json,
   0,1,NULL,'[]'
  FROM body_analysis_latest
  WHERE analysis_contract=? AND fatal_error=0
   AND EXISTS(SELECT 1 FROM current_body c WHERE c.sha256=body_analysis_latest.sha256)
  """,(contract,pipe,PREVIOUS_ANALYSIS_CONTRACT))
 return db.total_changes-before
def git_revision(repo):
 head=subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],text=True,capture_output=True,check=True).stdout.strip()
 dirty=subprocess.run(['git','-C',str(repo),'status','--porcelain','--untracked-files=all'],text=True,capture_output=True,check=True).stdout.strip()
 if dirty: raise SystemExit(f'working tree is dirty: {repo}; commit it or pass an explicit --pipeline-id')
 return head

def pipeline_id(explicit):
 if explicit:return explicit
 corpus=git_revision(REPO_ROOT)
 engine=git_revision(JS_REDOX_ROOT)
 return f'corpus:{corpus};js-redox:{engine}'
def read_paths(args):
 p=args.paths_file if args.paths_file else args.candidate_dir/f'{args.candidate}.txt'; rows=[Path(x) for x in p.read_text().splitlines() if x.strip()]; return rows[:args.limit] if args.limit else rows
def parse_sus(stdout):
 payload=json.loads(stdout);
 if payload.get('schema')!=SUS_CONTRACT: raise RuntimeError(f"unexpected sus-scan schema: {payload.get('schema')!r}")
 files=payload.get('files') or []
 if len(files)!=1: raise RuntimeError(f'expected one sus-scan file report, got {len(files)}')
 return files[0]
def analyze_one(path,deob,sus,contract,pipeline):
 input_sha=sha256_file(path)
 with tempfile.TemporaryDirectory(prefix='js-redox-progress-') as tmp:
  work=Path(tmp); output=work/f'{input_sha}.js'; report_path=work/'deob.json'
  cp=subprocess.run([str(deob),str(path),str(output),'--report',str(report_path)],text=True,capture_output=True)
  deob_error=None; deob_report=None
  if cp.returncode==0 and report_path.is_file() and output.is_file(): deob_report=json.loads(report_path.read_text()); scan_path=output
  else: deob_error=(cp.stderr or cp.stdout or f'exit {cp.returncode}').strip()[:4000]; scan_path=path
  sp=subprocess.run([str(sus),'--json',str(scan_path)],text=True,capture_output=True)
  if sp.returncode!=0: raise RuntimeError(f'sus-scan failed for {path}: {(sp.stderr or sp.stdout).strip()}')
  sf=parse_sus(sp.stdout); transforms=dict((deob_report or {}).get('transforms') or {})
  return {'sha256':input_sha,'analysis_contract':contract,'pipeline_id':pipeline,'observed_at':utc_now(),'input_path':str(path),'output_sha256':(deob_report or {}).get('output_sha256') or input_sha,'output_bytes':scan_path.stat().st_size,'deob_changed':int(bool((deob_report or {}).get('changed'))),'deob_iterations':(deob_report or {}).get('iterations'),'transform_total':sum(int(v) for v in transforms.values()),'transforms_json':json.dumps(transforms,sort_keys=True,separators=(',',':')),'deob_error':deob_error,'diagnostics':int(sf.get('diagnostics') or 0),'parser_fatal_error':int(bool(sf.get('parser_fatal_error'))),'fatal_error':int(bool(sf.get('fatal_error'))),'analysis_complete':int(sf.get('analysis_complete',True) is not False),'parse_recovery':sf.get('parse_recovery'),'opaque_parse_spans_json':json.dumps(sf.get('opaque_parse_spans') or [],sort_keys=True,separators=(',',':')),'raw_signal_count':int(sf.get('signal_count') or 0),'raw_cluster_count':len(sf.get('clusters') or []),'raw_top_score':int(sf.get('top_score') or 0),'raw_signal_kinds_json':json.dumps(sf.get('signal_kinds') or {},sort_keys=True,separators=(',',':')),'actionable_signal_count':int(sf.get('actionable_signal_count') or 0),'actionable_cluster_count':len(sf.get('actionable_clusters') or []),'actionable_top_score':int(sf.get('actionable_top_score') or 0),'actionable_signal_kinds_json':json.dumps(sf.get('actionable_signal_kinds') or {},sort_keys=True,separators=(',',':'))}
def write_row(db,row):
 keys=('sha256','analysis_contract','pipeline_id','observed_at','input_path','output_sha256','output_bytes','deob_changed','deob_iterations','transform_total','transforms_json','deob_error','diagnostics','fatal_error','raw_signal_count','raw_cluster_count','raw_top_score','raw_signal_kinds_json','actionable_signal_count','actionable_cluster_count','actionable_top_score','actionable_signal_kinds_json','parser_fatal_error','analysis_complete','parse_recovery','opaque_parse_spans_json')
 columns=','.join(keys); placeholders=','.join('?' for _ in keys)
 updates=','.join(f'{k}=excluded.{k}' for k in keys if k not in ('sha256','analysis_contract','pipeline_id'))
 db.execute(f"INSERT INTO body_analysis_run({columns}) VALUES({placeholders}) ON CONFLICT(sha256,analysis_contract,pipeline_id) DO UPDATE SET {updates}",tuple(row[k] for k in keys))

def refresh_candidate_lists(db,directory):
 spec=importlib.util.spec_from_file_location('catalog_builder',ROOT/'scripts/build-corpus-catalog.py'); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module.emit_candidates(db,directory,POST_CANDIDATE_NAMES)
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--database',type=Path,default=DEFAULT_DB); ap.add_argument('--candidate-dir',type=Path,default=DEFAULT_CANDIDATES); src=ap.add_mutually_exclusive_group(); src.add_argument('--candidate',default='quick-focus'); src.add_argument('--paths-file',type=Path); ap.add_argument('--deobfuscate-safe',type=Path,default=DEFAULT_DEOB); ap.add_argument('--sus-scan',type=Path,default=DEFAULT_SUS); ap.add_argument('--analysis-contract',default=ANALYSIS_CONTRACT); ap.add_argument('--pipeline-id'); ap.add_argument('--force',action='store_true'); ap.add_argument('--skip-candidate-refresh',action='store_true'); ap.add_argument('--jobs',type=int,default=1); ap.add_argument('--limit',type=int,default=0); ap.add_argument('--nice',type=int,default=10); args=ap.parse_args()
 if args.jobs<1: raise SystemExit('--jobs must be >= 1')
 if args.nice: os.nice(args.nice)
 for b in (args.deobfuscate_safe,args.sus_scan):
  if not b.is_file(): raise SystemExit(f'missing analyzer binary: {b}')
 paths=read_paths(args); pipe=pipeline_id(args.pipeline_id); db=sqlite3.connect(args.database); ensure_schema(db); migrated=migrate_previous_contract(db,args.analysis_contract,pipe);
 if migrated: print(f'analysis migrated={migrated} {PREVIOUS_ANALYSIS_CONTRACT}->{args.analysis_contract}',flush=True)
 current_by_path={r[1]:r[0] for r in db.execute('SELECT sha256, representative_path FROM current_body')}; current=set(current_by_path.values()); requested=len(paths); existing=set() if args.force else {r[0] for r in db.execute('SELECT sha256 FROM body_analysis_run WHERE analysis_contract=? AND pipeline_id=?',(args.analysis_contract,pipe))}; paths=[p for p in paths if current_by_path.get(str(p)) not in existing]; skipped_existing=requested-len(paths); done=0; errors=[]
 with ThreadPoolExecutor(max_workers=args.jobs) as pool:
  futures=[(p,pool.submit(analyze_one,p,args.deobfuscate_safe,args.sus_scan,args.analysis_contract,pipe)) for p in paths]
  for p,f in futures:
   try:
    row=f.result()
    if row['sha256'] not in current: raise RuntimeError(f"input hash is not in current corpus: {row['sha256']}")
    with db: write_row(db,row)
    done+=1
    if done%25==0: print(f'progress {done}/{len(paths)}',flush=True)
   except Exception as exc: errors.append({'path':str(p),'error':repr(exc)})
 counts={} if args.skip_candidate_refresh else refresh_candidate_lists(db,args.candidate_dir); query='SELECT COUNT(*),SUM(fatal_error=0 AND actionable_top_score=0 AND actionable_signal_count=0),SUM(fatal_error=0 AND actionable_top_score=0 AND actionable_signal_count>0),SUM(fatal_error=0 AND actionable_top_score>0),SUM(fatal_error!=0) FROM {} WHERE analysis_contract=?'; best=db.execute(query.format('body_analysis_best'),(args.analysis_contract,)).fetchone(); latest=db.execute(query.format('body_analysis_latest'),(args.analysis_contract,)).fetchone()
 report={'schema':'js-redox-corpus-progress/v1','analysis_contract':args.analysis_contract,'pipeline_id':pipe,'migrated_from_previous':migrated,'requested':requested,'scheduled':len(paths),'skipped_existing':skipped_existing,'recorded':done,'errors':errors,'best_known':{'total':int(best[0] or 0),'zero_signals':int(best[1] or 0),'weak_signals':int(best[2] or 0),'residual':int(best[3] or 0),'invalid':int(best[4] or 0)},'latest':{'total':int(latest[0] or 0),'zero_signals':int(latest[1] or 0),'weak_signals':int(latest[2] or 0),'residual':int(latest[3] or 0),'invalid':int(latest[4] or 0)},'candidates':{n:counts[n] for n in ('known-invalid','known-residual','known-weak-signals','known-zero','untested-interesting','quick-focus','regressed-from-best','llm-review-zero') if n in counts}}; print(json.dumps(report,indent=2)); db.close()
 if errors: raise SystemExit(1)
if __name__=='__main__': main()
