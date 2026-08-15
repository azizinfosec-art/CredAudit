import os, tempfile, zipfile, tarfile, sys
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, wait, FIRST_COMPLETED
from multiprocessing import Process, Queue
from typing import List, Dict, Tuple
from .utils.common import iter_files, match_globs, normalize_exts, load_ignore_file, redact_finding_records
from .parsers.extract import extract_text_from_file, TEXT_EXTS
from .detection.scan import scan_text, serialize_findings
from .cache import ScanCache
from . import __version__ as _VERSION

def _ignore_worker_keyboard_interrupt():
    try:
        import signal
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass

def _should_include(path: str, include_exts, include_globs, exclude_globs):
    if include_exts and os.path.splitext(path)[1].lower() not in include_exts:
        return False
    return match_globs(path, include_globs, exclude_globs)


def collect_files(
    root_path: str,
    include_exts,
    include_globs,
    exclude_globs,
    threads=8,
    ignore_globs=None,
    max_size_bytes=None,
    verbose=False,
) -> List[str]:
    include_exts = normalize_exts(include_exts)
    ignore_globs = (ignore_globs or [])
    paths = iter_files(root_path, prune_globs=list(exclude_globs or []) + list(ignore_globs or []))
    selected: List[str] = []

    def check(p):
        try:
            if not _should_include(p, include_exts, include_globs, exclude_globs):
                return None
            if ignore_globs:
                from fnmatch import fnmatch

                norm = p.replace('\\', '/')
                for pat in ignore_globs:
                    if fnmatch(norm, pat):
                        return None
            if max_size_bytes is not None:
                try:
                    if os.path.getsize(p) > max_size_bytes:
                        return None
                except Exception:
                    return None
            return p
        except Exception:
            return None

    def add_selected(res):
        if res:
            selected.append(res)
            if verbose:
                print(res)

    max_workers = max(1, int(threads or 1))
    if max_workers == 1:
        for path in paths:
            add_selected(check(path))
    else:
        pending = set()
        path_iter = iter(paths)
        max_pending = max_workers * 4

        def submit_next(tp):
            try:
                path = next(path_iter)
            except StopIteration:
                return False
            pending.add(tp.submit(check, path))
            return True

        with ThreadPoolExecutor(max_workers=max_workers) as tp:
            for _ in range(max_pending):
                if not submit_next(tp):
                    break
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done:
                    try:
                        add_selected(fut.result())
                    except Exception:
                        pass
                while len(pending) < max_pending:
                    if not submit_next(tp):
                        break
    # Deterministic ordering for stable output and --list
    try:
        selected.sort(key=lambda s: s.replace('\\\\','/').lower())
    except Exception:
        selected.sort()
    return selected


def _scan_file_inner(p, ent_min, ent_thr, har_include: str | None = 'both', har_max_body_bytes: int | None = None, rule_level: int | None = None, only_rules=None):
    ext = os.path.splitext(p)[1].lower()
    if ext == '.har':
        try:
            from .parsers.har import iter_har_texts
            include_requests = (har_include in (None, 'both', 'requests'))
            include_responses = (har_include in (None, 'both', 'responses'))
            if har_max_body_bytes is None:
                try:
                    import os as _os
                    har_max_body_bytes = int(_os.environ.get('CREDAUDIT_HAR_MAX_BODY_BYTES', str(2*1024*1024)))
                except Exception:
                    har_max_body_bytes = 2*1024*1024
            allf = []
            for vid, txt in iter_har_texts(p, include_requests=include_requests, include_responses=include_responses,
                                           max_body_bytes=int(har_max_body_bytes)):
                allf.extend(serialize_findings(scan_text(vid, txt, ent_min, ent_thr, rule_level, only_rules)))
            return p, allf, 'ok'
        except Exception:
            return p, [], 'unreadable'
    t = extract_text_from_file(p)
    if t is None:
        return p, [], 'unreadable'
    return p, serialize_findings(scan_text(p, t, ent_min, ent_thr, rule_level, only_rules)), 'ok'


def _scan_file_runner(q: Queue, p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level, only_rules):
    _ignore_worker_keyboard_interrupt()
    try:
        res = _scan_file_inner(p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level, only_rules)
    except KeyboardInterrupt:
        res = (p, [], 'interrupted')
    except Exception:
        res = (p, [], 'error')
    try:
        q.put(res)
    except Exception:
        pass


def _inline_timeout_text_limit() -> int:
    try:
        return int(os.environ.get("CREDAUDIT_INLINE_TEXT_TIMEOUT_MAX_BYTES", str(1024 * 1024)))
    except Exception:
        return 1024 * 1024


def _can_scan_inline_with_timeout(path: str) -> bool:
    if os.path.splitext(path)[1].lower() not in TEXT_EXTS:
        return False
    try:
        return os.path.getsize(path) <= _inline_timeout_text_limit()
    except Exception:
        return False


def _scan_file(p, ent_min, ent_thr, har_include: str | None = 'both', har_max_body_bytes: int | None = None, rule_level: int | None = None, per_file_timeout: float | None = None, only_rules=None):
    # If no timeout configured, run inline in this process (original behavior)
    if not per_file_timeout or per_file_timeout <= 0:
        return _scan_file_inner(p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level, only_rules)
    if _can_scan_inline_with_timeout(p):
        try:
            return _scan_file_inner(p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level, only_rules)
        except KeyboardInterrupt:
            return p, [], 'interrupted'
        except Exception:
            return p, [], 'error'
    # Run actual scan in a child process so we can terminate on timeout
    try:
        q: Queue = Queue(maxsize=1)
        proc = Process(target=_scan_file_runner, args=(q, p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level, only_rules))
        proc.daemon = True
        proc.start()
        proc.join(per_file_timeout)
        if proc.is_alive():
            try:
                proc.terminate()
            finally:
                try:
                    proc.join(1)
                except Exception:
                    pass
            return p, [], 'timeout'
        try:
            res = q.get_nowait()
            return res
        except Exception:
            return p, [], 'error'
    except Exception:
        return p, [], 'error'


def _confidence_value(record: dict) -> int:
    try:
        return int(record.get("confidence", 0) or 0)
    except Exception:
        return 0


def _filter_by_confidence(records: List[dict], min_confidence: int | None = None) -> List[dict]:
    if min_confidence is None:
        return list(records or [])
    threshold = max(0, min(100, int(min_confidence)))
    return [r for r in (records or []) if _confidence_value(r) >= threshold]


def _effective_har_max_body_bytes(value: int | None = None) -> int:
    if value is not None:
        try:
            return int(value)
        except Exception:
            return 2 * 1024 * 1024
    try:
        return int(os.environ.get('CREDAUDIT_HAR_MAX_BODY_BYTES', str(2 * 1024 * 1024)))
    except Exception:
        return 2 * 1024 * 1024


def _normalized_only_rules(only_rules) -> List[str] | None:
    if only_rules is None:
        return None
    values = sorted({str(rule).strip() for rule in only_rules if str(rule).strip()})
    return values


def _scan_profile(entropy_min_len, entropy_thresh, har_include, har_max_body_bytes, rule_level, only_rules) -> dict:
    return {
        "version": _VERSION,
        "entropy_min_len": int(entropy_min_len),
        "entropy_thresh": float(entropy_thresh),
        "har_include": har_include or "both",
        "har_max_body_bytes": int(har_max_body_bytes),
        "rule_level": rule_level,
        "only_rules": _normalized_only_rules(only_rules),
    }


def scan_paths(
    paths: List[str],
    output_dir: str,
    formats: List[str],
    timestamp: bool,
    cache_file: str,
    entropy_min_len: int,
    entropy_thresh: float,
    workers: int | None,
    fail_on: str | None,
    scan_archives_flag: bool,
    archive_depth: int,
    verbose: bool,
    no_cache: bool = False,
    har_include: str | None = 'both',
    har_max_body_bytes: int | None = None,
    rule_level: int | None = None,
    ndjson_out: str | None = None,
    ndjson_truncate: bool | None = None,
    ndjson_flush_sec: float | None = None,
    ndjson_buffer: int | None = None,
    ndjson_include_raw: bool | None = None,
    per_file_timeout: float | None = None,
    only_rules = None,
    safe_report: bool = False,
    min_confidence: int | None = None,
    max_size_bytes: int | None = None,
):
    if formats:
        os.makedirs(output_dir, exist_ok=True)
    from .exporters.json_exporter import export_json
    from .exporters.csv_exporter import export_csv
    from .exporters.html_exporter import export_html
    from .exporters.sarif_exporter import export_sarif

    findings_all = []
    effective_har_max_body_bytes = _effective_har_max_body_bytes(har_max_body_bytes)
    cache_profile = _scan_profile(
        entropy_min_len,
        entropy_thresh,
        har_include,
        effective_har_max_body_bytes,
        rule_level,
        only_rules,
    )
    cache_enabled = not no_cache and not safe_report
    cache = ScanCache(cache_file) if cache_enabled else None
    to_scan = []
    if not cache_enabled:
        to_scan = list(paths)
    else:
        for p in paths:
            if cache and cache.is_unchanged(p, cache_profile):
                cached = cache.get_findings(p)
                if cached:
                    if min_confidence is not None and any("confidence" not in rec for rec in cached):
                        if verbose:
                            print(f"[CACHE] unchanged {p}, but cached findings lack confidence; queueing for scan")
                        to_scan.append(p)
                        continue
                    cached_visible = _filter_by_confidence(cached, min_confidence)
                    findings_all.extend(cached_visible)
                    if verbose:
                        print(f"[CACHE] reused {len(cached_visible)} findings from {p}")
                else:
                    if verbose:
                        print(f"[CACHE] unchanged {p}, but no cached findings; queueing for scan")
                    to_scan.append(p)
            else:
                to_scan.append(p)
    # Optional: expand archives into a temporary directory for scanning
    path_alias: Dict[str, str] = {}

    def _is_archive(path: str) -> bool:
        lp = path.lower()
        return lp.endswith('.zip') or lp.endswith('.rar') or lp.endswith('.tar') or lp.endswith('.tgz') or lp.endswith('.tar.gz')

    allowed_exts = set(TEXT_EXTS) | {'.docx', '.pdf', '.xlsx', '.har'}

    def _safe_join(base: str, *parts: str) -> str:
        base_abs = os.path.abspath(base)
        dest = os.path.abspath(os.path.normpath(os.path.join(base_abs, *parts)))
        if not (dest == base_abs or dest.startswith(base_abs + os.sep)):
            raise RuntimeError('Unsafe path outside extraction directory')
        return dest

    def _member_too_large(size) -> bool:
        try:
            return max_size_bytes is not None and int(size) > int(max_size_bytes)
        except Exception:
            return False

    def _copy_limited(src, dest: str) -> bool:
        total = 0
        try:
            with open(dest, 'wb') as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        return True
                    total += len(chunk)
                    if _member_too_large(total):
                        return False
                    dst.write(chunk)
        finally:
            if _member_too_large(total):
                try:
                    os.remove(dest)
                except Exception:
                    pass

    def _post_extract(archive_path: str, added: List[Tuple[str, str]], out_dir: str, depth: int) -> List[str]:
        results: List[str] = []
        for real, rel in added:
            rel_norm = rel.replace('\\', '/')
            if _is_archive(real) and depth > 0:
                # Recurse into nested archives
                sub_dir = _safe_join(out_dir, os.path.splitext(rel)[0] + '_x')
                os.makedirs(sub_dir, exist_ok=True)
                results.extend(_expand_any(real, sub_dir, depth - 1))
                continue
            ext = os.path.splitext(real)[1].lower()
            if allowed_exts and ext not in allowed_exts:
                try:
                    os.remove(real)
                except Exception:
                    pass
                continue
            path_alias[real] = f"{archive_path}!{rel_norm}"
            results.append(real)
        return results

    def _expand_zip(zip_path: str, out_dir: str, depth: int) -> List[str]:
        added: List[Tuple[str, str]] = []
        try:
            with zipfile.ZipFile(zip_path) as z:
                for info in z.infolist():
                    n = info.filename
                    if n.endswith('/'):
                        continue
                    if _member_too_large(info.file_size):
                        continue
                    dest = _safe_join(out_dir, n)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with z.open(n, 'r') as src:
                        if not _copy_limited(src, dest):
                            continue
                    added.append((dest, n))
        except Exception:
            return []
        return _post_extract(zip_path, added, out_dir, depth)

    def _expand_tar(tar_path: str, out_dir: str, depth: int) -> List[str]:
        added: List[Tuple[str, str]] = []
        try:
            mode = 'r'
            lp = tar_path.lower()
            if lp.endswith('.tar.gz') or lp.endswith('.tgz'):
                mode = 'r:gz'
            with tarfile.open(tar_path, mode) as t:
                for m in t.getmembers():
                    if not m.isfile():
                        continue
                    if _member_too_large(m.size):
                        continue
                    dest = _safe_join(out_dir, m.name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    f = t.extractfile(m)
                    if not f:
                        continue
                    if not _copy_limited(f, dest):
                        continue
                    added.append((dest, m.name))
        except Exception:
            return []
        return _post_extract(tar_path, added, out_dir, depth)

    def _expand_rar(rar_path: str, out_dir: str, depth: int) -> List[str]:
        added: List[Tuple[str, str]] = []
        try:
            import rarfile  # lazy import
            with rarfile.RarFile(rar_path) as rf:
                for info in rf.infolist():
                    if info.is_dir():
                        continue
                    if _member_too_large(getattr(info, 'file_size', 0)):
                        continue
                    dest = _safe_join(out_dir, info.filename)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with rf.open(info, 'r') as src:
                        if not _copy_limited(src, dest):
                            continue
                    added.append((dest, info.filename))
        except Exception:
            return []
        return _post_extract(rar_path, added, out_dir, depth)

    def _expand_any(path: str, out_dir: str, depth: int) -> List[str]:
        lp = path.lower()
        if lp.endswith('.zip'):
            return _expand_zip(path, out_dir, depth)
        if lp.endswith('.rar'):
            return _expand_rar(path, out_dir, depth)
        if lp.endswith('.tar') or lp.endswith('.tar.gz') or lp.endswith('.tgz'):
            return _expand_tar(path, out_dir, depth)
        return []

    tmp_ctx = None
    if scan_archives_flag and to_scan:
        tmp_ctx = tempfile.TemporaryDirectory(prefix='credaudit_ar_')
        tmp_root = tmp_ctx.name
        expanded: List[str] = []
        for p in to_scan:
            if _is_archive(p):
                sub = os.path.join(tmp_root, os.path.basename(p) + '_x')
                os.makedirs(sub, exist_ok=True)
                expanded.extend(_expand_any(p, sub, max(0, int(archive_depth or 0))))
            else:
                expanded.append(p)
        to_scan = expanded

    # Friendly progress: minimal spinner when interactive and not verbose
    show_spinner = sys.stdout.isatty() and not verbose
    spinner = ['|','/','-','\\']
    spin_idx = 0
    done = 0

    if verbose:
        # One-time tip line in verbose mode
        print("Tip: Use --timestamp to version reports; set CREDAUDIT_HTML_MAX_ROWS to limit HTML size; use --no-cache to force rescan.")

    nd_writer = None
    if ndjson_out:
        try:
            from .exporters.ndjson_exporter import NDJSONWriter
            nd_writer = NDJSONWriter(
                ndjson_out,
                truncate=bool(ndjson_truncate or False),
                flush_sec=float(ndjson_flush_sec or 1.0),
                buffer_size=int(ndjson_buffer or 100),
                include_raw=bool(ndjson_include_raw or False) and not safe_report,
            )
        except Exception:
            nd_writer = None

    if to_scan:
        total = len(to_scan)
        max_workers = workers or os.cpu_count() or 2
        progress_len = 0

        def emit_progress():
            nonlocal spin_idx, progress_len
            if not show_spinner:
                return
            spin = spinner[spin_idx % len(spinner)]
            spin_idx += 1
            busy = min(max_workers, max(0, total - done))
            msg = f"\r{spin} Scanning {done}/{total} | Busy: {busy} | Findings: {len(findings_all)} "
            pad = " " * max(0, progress_len - len(msg))
            sys.stdout.write(msg + pad)
            sys.stdout.flush()
            progress_len = len(msg)

        emit_progress()
        pp = ProcessPoolExecutor(max_workers=max_workers, initializer=_ignore_worker_keyboard_interrupt)
        shutdown_done = False
        try:
            futs = {pp.submit(_scan_file, p, entropy_min_len, entropy_thresh, har_include, effective_har_max_body_bytes, rule_level, per_file_timeout, only_rules): p for p in to_scan}
            try:
                pending = set(futs)
                while pending:
                    completed, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
                    if not completed:
                        emit_progress()
                        continue
                    for fut in completed:
                        p = futs[fut]
                        try:
                            _, f, st = fut.result()
                            if st == 'ok':
                                if f:
                                    if path_alias:
                                        for rec in f:
                                            fp = rec.get('file')
                                            if fp in path_alias:
                                                rec['file'] = path_alias[fp]
                                    visible_findings = _filter_by_confidence(f, min_confidence)
                                    findings_all.extend(visible_findings)
                                    if nd_writer is not None:
                                        try:
                                            nd_writer.add_findings(visible_findings)
                                        except Exception:
                                            pass
                                if cache_enabled and cache:
                                    cache.update(p, f, cache_profile)
                            elif st in ('timeout', 'error', 'interrupted'):
                                if verbose:
                                    print(f"[SKIP] {p}: {st}")
                        except Exception as e:
                            if verbose:
                                print(f"[SKIP] {p}: exception {e}")
                        finally:
                            done += 1
                            emit_progress()
            except KeyboardInterrupt:
                for fut in futs:
                    fut.cancel()
                pp.shutdown(wait=False, cancel_futures=True)
                shutdown_done = True
                raise
        finally:
            if not shutdown_done:
                pp.shutdown(wait=True)
        if show_spinner:
            print()  # newline after spinner
    # Deterministic ordering for exported reports (JSON/CSV/HTML/SARIF)
    try:
        findings_all.sort(key=lambda r: (
            str(r.get('file','')).replace('\\\\','/').lower(),
            int(r.get('line', 0) or 0),
            str(r.get('rule',''))
        ))
    except Exception:
        pass

    if nd_writer is not None:
        try:
            nd_writer.close()
        except Exception:
            pass
    if cache_enabled and cache:
        cache.save()
    import datetime as _dt

    stamp = '_' + _dt.datetime.now().strftime('%Y%m%d_%H%M%S') if timestamp else ''
    base = os.path.join(output_dir, f'report{stamp}')
    export_findings = redact_finding_records(findings_all) if safe_report else findings_all
    if 'json' in formats:
        export_json(export_findings, base + '.json')
    if 'csv' in formats:
        export_csv(export_findings, base + '.csv')
    if 'html' in formats:
        export_html(export_findings, base + '.html', redacted_only=safe_report)
    if 'sarif' in formats:
        export_sarif(export_findings, base + '.sarif')
    code = 0
    sev_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    if fail_on:
        thr = sev_order[fail_on]
        worst = max([sev_order.get(f.get("severity", "Low"), 1) for f in findings_all] or [1])
        if worst >= thr:
            code = 2
    return findings_all, code
