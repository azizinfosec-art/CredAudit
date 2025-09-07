import os, tempfile, zipfile, tarfile, sys
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from multiprocessing import Process, Queue
from typing import List, Dict, Tuple
from .utils.common import iter_files, match_globs, normalize_exts, load_ignore_file
from .parsers.extract import extract_text_from_file, TEXT_EXTS
from .detection.scan import scan_text, serialize_findings
from .cache import ScanCache


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
    paths = list(iter_files(root_path))
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

    with ThreadPoolExecutor(max_workers=threads) as tp:
        for res in tp.map(check, paths):
            if res:
                selected.append(res)
                if verbose:
                    print(res)
    # Deterministic ordering for stable output and --list
    try:
        selected.sort(key=lambda s: s.replace('\\\\','/').lower())
    except Exception:
        selected.sort()
    return selected


def _scan_file_inner(p, ent_min, ent_thr, har_include: str | None = 'both', har_max_body_bytes: int | None = None, rule_level: int | None = None):
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
                allf.extend(serialize_findings(scan_text(vid, txt, ent_min, ent_thr, rule_level)))
            return p, allf, 'ok'
        except Exception:
            return p, [], 'unreadable'
    t = extract_text_from_file(p)
    if t is None:
        return p, [], 'unreadable'
    return p, serialize_findings(scan_text(p, t, ent_min, ent_thr, rule_level)), 'ok'


def _scan_file_runner(q: Queue, p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level):
    try:
        res = _scan_file_inner(p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level)
    except Exception:
        res = (p, [], 'error')
    try:
        q.put(res)
    except Exception:
        pass


def _scan_file(p, ent_min, ent_thr, har_include: str | None = 'both', har_max_body_bytes: int | None = None, rule_level: int | None = None, per_file_timeout: float | None = None):
    # If no timeout configured, run inline in this process (original behavior)
    if not per_file_timeout or per_file_timeout <= 0:
        return _scan_file_inner(p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level)
    # Run actual scan in a child process so we can terminate on timeout
    try:
        q: Queue = Queue(maxsize=1)
        proc = Process(target=_scan_file_runner, args=(q, p, ent_min, ent_thr, har_include, har_max_body_bytes, rule_level))
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
):
    os.makedirs(output_dir, exist_ok=True)
    from .exporters.json_exporter import export_json
    from .exporters.csv_exporter import export_csv
    from .exporters.html_exporter import export_html
    from .exporters.sarif_exporter import export_sarif

    findings_all = []
    cache = ScanCache(cache_file)
    to_scan = []
    if no_cache:
        to_scan = list(paths)
    else:
        for p in paths:
            if cache.is_unchanged(p):
                cached = cache.get_findings(p)
                if cached:
                    findings_all.extend(cached)
                    if verbose:
                        print(f"[CACHE] reused {len(cached)} findings from {p}")
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

    allowed_exts = set(TEXT_EXTS) | {'.docx', '.pdf', '.xlsx'}

    def _safe_join(base: str, *parts: str) -> str:
        base_abs = os.path.abspath(base)
        dest = os.path.abspath(os.path.normpath(os.path.join(base_abs, *parts)))
        if not (dest == base_abs or dest.startswith(base_abs + os.sep)):
            raise RuntimeError('Unsafe path outside extraction directory')
        return dest

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
                for n in z.namelist():
                    if n.endswith('/'):
                        continue
                    dest = _safe_join(out_dir, n)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with z.open(n, 'r') as src, open(dest, 'wb') as dst:
                        dst.write(src.read())
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
                    dest = _safe_join(out_dir, m.name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    f = t.extractfile(m)
                    if not f:
                        continue
                    with open(dest, 'wb') as dst:
                        dst.write(f.read())
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
                    dest = _safe_join(out_dir, info.filename)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with rf.open(info, 'r') as src, open(dest, 'wb') as dst:
                        dst.write(src.read())
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
                include_raw=bool(ndjson_include_raw or False),
            )
        except Exception:
            nd_writer = None

    if to_scan:
        total = len(to_scan)
        if show_spinner:
            print(f"Scanning {done}/{total} | Findings: {len(findings_all)} ", end='', flush=True)
        with ProcessPoolExecutor(max_workers=workers or os.cpu_count() or 2) as pp:
            futs = {pp.submit(_scan_file, p, entropy_min_len, entropy_thresh, har_include, har_max_body_bytes, rule_level, per_file_timeout): p for p in to_scan}
            for fut in as_completed(futs):
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
                            findings_all.extend(f)
                            if nd_writer is not None:
                                try:
                                    nd_writer.add_findings(f)
                                except Exception:
                                    pass
                        if not no_cache:
                            cache.update(p, f)
                    elif st in ('timeout', 'error'):
                        if verbose:
                            print(f"[SKIP] {p}: {st}")
                except Exception as e:
                    if verbose:
                        print(f"[SKIP] {p}: exception {e}")
                finally:
                    done += 1
                    if show_spinner:
                        spin = spinner[spin_idx % len(spinner)]; spin_idx += 1
                        msg = f"\r{spin} Scanning {done}/{total} | Findings: {len(findings_all)} "
                        # Pad/truncate to avoid leftover chars
                        sys.stdout.write(msg)
                        sys.stdout.flush()
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
    if not no_cache:
        cache.save()
    import datetime as _dt

    stamp = '_' + _dt.datetime.now().strftime('%Y%m%d_%H%M%S') if timestamp else ''
    base = os.path.join(output_dir, f'report{stamp}')
    if 'json' in formats:
        export_json(findings_all, base + '.json')
    if 'csv' in formats:
        export_csv(findings_all, base + '.csv')
    if 'html' in formats:
        export_html(findings_all, base + '.html')
    if 'sarif' in formats:
        export_sarif(findings_all, base + '.sarif')
    code = 0
    sev_order = {"Low": 1, "Medium": 2, "High": 3}
    if fail_on:
        thr = sev_order[fail_on]
        worst = max([sev_order.get(f.get("severity", "Low"), 1) for f in findings_all] or [1])
        if worst >= thr:
            code = 2
    return findings_all, code
