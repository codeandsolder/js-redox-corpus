#!/usr/bin/env python3
"""Incrementally cache parser-level sus-scan summaries for every current JavaScript body."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from corpus_env import CORPUS_ROOT, JS_REDOX_ROOT, REPO_ROOT

DEFAULT_CORPUS = CORPUS_ROOT
DEFAULT_DB = DEFAULT_CORPUS / "preclass/corpus.sqlite"
DEFAULT_CANDIDATES = DEFAULT_CORPUS / "preclass/candidates"
DEFAULT_SUS = JS_REDOX_ROOT / ".cargo-target-nodebug/release/sus-scan"
SEMANTIC_CONTRACT = "js-sus-scan/v5"
PREVIOUS_SEMANTIC_CONTRACT = "js-sus-scan/v4"

SEMANTIC_CANDIDATE_NAMES = (
    "semantic-actionable",
    "semantic-weak-signals",
    "semantic-invalid",
    "semantic-zero",
    "decode-anomaly",
)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds")


def ensure_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS body_semantic_scan (
          sha256 TEXT NOT NULL,
          scan_contract TEXT NOT NULL,
          scanned_at TEXT NOT NULL,
          diagnostics INTEGER NOT NULL,
          fatal_error INTEGER NOT NULL,
          raw_signal_count INTEGER NOT NULL,
          raw_cluster_count INTEGER NOT NULL,
          raw_top_score INTEGER NOT NULL,
          raw_signal_kinds_json TEXT NOT NULL,
          actionable_signal_count INTEGER NOT NULL,
          actionable_cluster_count INTEGER NOT NULL,
          actionable_top_score INTEGER NOT NULL,
          actionable_signal_kinds_json TEXT NOT NULL,
          PRIMARY KEY (sha256, scan_contract)
        );
        CREATE INDEX IF NOT EXISTS semantic_contract_idx
          ON body_semantic_scan(scan_contract, sha256);
        CREATE INDEX IF NOT EXISTS semantic_actionable_idx
          ON body_semantic_scan(scan_contract, fatal_error, actionable_top_score, actionable_signal_count);
        CREATE TABLE IF NOT EXISTS body_representation_edge (
          transport_sha256 TEXT NOT NULL, browser_sha256 TEXT NOT NULL,
          capture TEXT NOT NULL, url TEXT NOT NULL, evidence TEXT NOT NULL,
          PRIMARY KEY (transport_sha256, browser_sha256, capture, url)
        ) WITHOUT ROWID;
    """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(body_semantic_scan)")}
    additions = {
        "decode_encoding": "TEXT NOT NULL DEFAULT 'UTF-8'",
        "decode_source": "TEXT NOT NULL DEFAULT 'legacy'",
        "decode_had_errors": "INTEGER NOT NULL DEFAULT 0",
        "decode_uncertain": "INTEGER NOT NULL DEFAULT 0",
        "parser_fatal_error": "INTEGER NOT NULL DEFAULT 0",
        "analysis_complete": "INTEGER NOT NULL DEFAULT 1",
        "parse_recovery": "TEXT",
        "opaque_parse_spans_json": "TEXT NOT NULL DEFAULT '[]'",
    }
    for name, declaration in additions.items():
        if name not in columns:
            db.execute(f"ALTER TABLE body_semantic_scan ADD COLUMN {name} {declaration}")


def migrate_previous_contract(db: sqlite3.Connection) -> int:
    """Carry forward v4 rows unaffected by the v5 codec-signal policy.

    v5 keeps parser/decoder behavior unchanged, but generic dynamic char-code,
    base64-decoder, and radix-conversion calls stop being actionable on their
    own. Rows containing any of those old actionable kinds must be re-scanned
    because cluster scores can change; every other non-fatal v4 row is exact.
    """
    before = db.total_changes
    with db:
        db.execute(
            """
            INSERT OR IGNORE INTO body_semantic_scan (
              sha256,scan_contract,scanned_at,diagnostics,fatal_error,
              raw_signal_count,raw_cluster_count,raw_top_score,raw_signal_kinds_json,
              actionable_signal_count,actionable_cluster_count,actionable_top_score,
              actionable_signal_kinds_json,decode_encoding,decode_source,
              decode_had_errors,decode_uncertain,parser_fatal_error,analysis_complete,
              parse_recovery,opaque_parse_spans_json
            )
            SELECT old.sha256,?,old.scanned_at,old.diagnostics,old.fatal_error,
                   old.raw_signal_count,old.raw_cluster_count,old.raw_top_score,old.raw_signal_kinds_json,
                   old.actionable_signal_count,old.actionable_cluster_count,old.actionable_top_score,
                   old.actionable_signal_kinds_json,old.decode_encoding,old.decode_source,
                   old.decode_had_errors,old.decode_uncertain,old.parser_fatal_error,old.analysis_complete,
                   old.parse_recovery,old.opaque_parse_spans_json
            FROM body_semantic_scan old
            WHERE old.scan_contract=? AND old.fatal_error=0
              AND old.actionable_signal_kinds_json NOT LIKE '%"charcode_decode_call"%'
              AND old.actionable_signal_kinds_json NOT LIKE '%"base64_decode_call"%'
              AND old.actionable_signal_kinds_json NOT LIKE '%"radix_string_call"%'
              AND EXISTS (SELECT 1 FROM current_body c WHERE c.sha256=old.sha256)
              AND NOT EXISTS (
                SELECT 1 FROM body_representation_edge e
                WHERE e.transport_sha256=old.sha256 AND e.evidence LIKE 'exact:%'
              )
            """,
            (SEMANTIC_CONTRACT, PREVIOUS_SEMANTIC_CONTRACT),
        )
    return db.total_changes - before


def emit_candidates(db: sqlite3.Connection, directory: Path) -> dict[str, int]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("catalog_builder", REPO_ROOT / "scripts/build-corpus-catalog.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load catalog builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.emit_candidates(db, directory, SEMANTIC_CANDIDATE_NAMES)


def chunks(items: list[tuple[str, str]], size: int):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def scan_chunk(binary: Path, chunk: list[tuple[str, str]]) -> list[dict]:
    paths = [path for _, path in chunk]
    cp = subprocess.run(
        [str(binary), "--json", *paths],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode:
        raise RuntimeError(f"sus-scan failed: {(cp.stderr or cp.stdout).strip()}")
    payload = json.loads(cp.stdout)
    if payload.get("schema") != SEMANTIC_CONTRACT:
        raise RuntimeError(f"unexpected sus-scan schema: {payload.get('schema')!r}")
    by_path = {str(Path(row["input"])): row for row in payload.get("files") or []}
    results = []
    scanned_at = utc_now()
    for digest, path in chunk:
        row = by_path.get(str(Path(path)))
        if row is None:
            raise RuntimeError(f"sus-scan omitted input: {path}")
        results.append(
            {
                "sha256": digest,
                "scan_contract": SEMANTIC_CONTRACT,
                "scanned_at": scanned_at,
                "decode_encoding": str(row.get("decode_encoding") or "UTF-8"),
                "decode_source": str(row.get("decode_source") or "legacy"),
                "decode_had_errors": int(bool(row.get("decode_had_errors"))),
                "decode_uncertain": int(bool(row.get("decode_uncertain"))),
                "parser_fatal_error": int(bool(row.get("parser_fatal_error"))),
                "analysis_complete": int(row.get("analysis_complete", True) is not False),
                "parse_recovery": row.get("parse_recovery"),
                "opaque_parse_spans_json": json.dumps(row.get("opaque_parse_spans") or [], sort_keys=True, separators=(",", ":")),
                "diagnostics": int(row.get("diagnostics") or 0),
                "fatal_error": int(bool(row.get("fatal_error"))),
                "raw_signal_count": int(row.get("signal_count") or 0),
                "raw_cluster_count": len(row.get("clusters") or []),
                "raw_top_score": int(row.get("top_score") or 0),
                "raw_signal_kinds_json": json.dumps(row.get("signal_kinds") or {}, sort_keys=True, separators=(",", ":")),
                "actionable_signal_count": int(row.get("actionable_signal_count") or 0),
                "actionable_cluster_count": len(row.get("actionable_clusters") or []),
                "actionable_top_score": int(row.get("actionable_top_score") or 0),
                "actionable_signal_kinds_json": json.dumps(row.get("actionable_signal_kinds") or {}, sort_keys=True, separators=(",", ":")),
            }
        )
    return results


def store(db: sqlite3.Connection, rows: list[dict]) -> None:
    keys = (
        "sha256", "scan_contract", "scanned_at", "diagnostics", "fatal_error",
        "raw_signal_count", "raw_cluster_count", "raw_top_score", "raw_signal_kinds_json",
        "actionable_signal_count", "actionable_cluster_count", "actionable_top_score",
        "actionable_signal_kinds_json", "decode_encoding", "decode_source",
        "decode_had_errors", "decode_uncertain", "parser_fatal_error", "analysis_complete",
        "parse_recovery", "opaque_parse_spans_json",
    )
    columns = ",".join(keys)
    placeholders = ",".join("?" for _ in keys)
    db.executemany(
        f"INSERT OR REPLACE INTO body_semantic_scan ({columns}) VALUES ({placeholders})",
        [tuple(row[key] for key in keys) for row in rows],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument("--candidate-dir", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--sus-scan", type=Path, default=DEFAULT_SUS)
    parser.add_argument("--chunk-size", type=int, default=256)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--nice", type=int, default=10)
    parser.add_argument("--skip-candidate-refresh", action="store_true")
    args = parser.parse_args()
    if args.chunk_size < 1:
        raise SystemExit("--chunk-size must be >= 1")
    if args.jobs < 1:
        raise SystemExit("--jobs must be >= 1")
    if args.nice:
        os.nice(args.nice)
    if not args.sus_scan.is_file():
        raise SystemExit(f"missing sus-scan binary: {args.sus_scan}")

    db = sqlite3.connect(args.database)
    ensure_schema(db)
    migrated = migrate_previous_contract(db)
    if migrated:
        print(f"semantic migrated={migrated} {PREVIOUS_SEMANTIC_CONTRACT}->{SEMANTIC_CONTRACT}", flush=True)
    all_pending = list(
        db.execute(
            """
            SELECT c.sha256,c.representative_path
            FROM current_body c JOIN body_scan s USING (sha256)
            WHERE s.content_kind >= 'javascript' AND s.content_kind < 'javascripu' AND s.nuisance IS NULL
              AND NOT EXISTS (
                SELECT 1 FROM body_representation_edge e
                WHERE e.transport_sha256=c.sha256 AND e.evidence LIKE 'exact:%'
              )
              AND NOT EXISTS (
                SELECT 1 FROM body_semantic_scan ss
                WHERE ss.sha256=c.sha256 AND ss.scan_contract=?
              )
            ORDER BY c.sha256
            """,
            (SEMANTIC_CONTRACT,),
        )
    )
    pending = all_pending[:args.limit] if args.limit else all_pending
    print(f"semantic pending={len(pending)} contract={SEMANTIC_CONTRACT}", flush=True)
    done = 0
    work = list(chunks(pending, args.chunk_size))
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(scan_chunk, args.sus_scan, chunk): len(chunk) for chunk in work}
        for future in as_completed(futures):
            rows = future.result()
            with db:
                store(db, rows)
            done += len(rows)
            print(f"semantic {done}/{len(pending)} jobs={args.jobs}", flush=True)

    counts = {} if args.skip_candidate_refresh else emit_candidates(db, args.candidate_dir)
    if not args.skip_candidate_refresh:
        # We already computed the complete canonical untested set before scanning.
        # Avoid proving the same absence again with hundreds of thousands of indexed
        # anti-joins: after a successful run only the deliberately unprocessed tail
        # can remain untested. all_pending is SHA-ordered, so the file is stable.
        remaining_untested = all_pending[len(pending):]
        args.candidate_dir.mkdir(parents=True, exist_ok=True)
        (args.candidate_dir / "semantic-untested.txt").write_text(
            "".join(f"{path}\n" for _, path in remaining_untested), encoding="utf-8"
        )
        counts["semantic-untested"] = len(remaining_untested)
    totals = db.execute(
        """
        SELECT COUNT(*),
               SUM(fatal_error=0 AND actionable_top_score=0 AND actionable_signal_count=0),
               SUM(fatal_error=0 AND actionable_top_score=0 AND actionable_signal_count>0),
               SUM(fatal_error=0 AND actionable_top_score>0),
               SUM(fatal_error!=0)
        FROM body_semantic_scan ss JOIN current_body c USING (sha256)
        WHERE scan_contract=?
        """,
        (SEMANTIC_CONTRACT,),
    ).fetchone()
    report = {
        "schema": "js-redox-corpus-semantic-index/v1",
        "scan_contract": SEMANTIC_CONTRACT,
        "migrated_from_previous": migrated,
        "newly_scanned": done,
        "current_scanned": int(totals[0] or 0),
        "current_zero": int(totals[1] or 0),
        "current_weak_signals": int(totals[2] or 0),
        "current_actionable": int(totals[3] or 0),
        "current_invalid": int(totals[4] or 0),
        "decode_anomalies": int(db.execute(
            "SELECT COUNT(*) FROM body_semantic_scan WHERE scan_contract=? AND decode_had_errors!=0",
            (SEMANTIC_CONTRACT,),
        ).fetchone()[0]),
        "parser_fatal_inputs": int(db.execute(
            "SELECT COUNT(*) FROM body_semantic_scan WHERE scan_contract=? AND parser_fatal_error!=0",
            (SEMANTIC_CONTRACT,),
        ).fetchone()[0]),
        "parse_recovered": int(db.execute(
            "SELECT COUNT(*) FROM body_semantic_scan WHERE scan_contract=? AND parse_recovery IS NOT NULL",
            (SEMANTIC_CONTRACT,),
        ).fetchone()[0]),
        "incomplete_analysis": int(db.execute(
            "SELECT COUNT(*) FROM body_semantic_scan WHERE scan_contract=? AND analysis_complete=0",
            (SEMANTIC_CONTRACT,),
        ).fetchone()[0]),
        "candidates": {
            name: counts[name]
            for name in ("semantic-actionable", "semantic-weak-signals", "semantic-invalid", "semantic-zero", "semantic-untested")
            if name in counts
        },
    }
    print(json.dumps(report, indent=2))
    db.close()


if __name__ == "__main__":
    main()
