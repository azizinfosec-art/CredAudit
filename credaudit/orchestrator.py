import os
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from typing import List
from .utils.common import iter_files, match_globs, normalize_exts, load_ignore_file
from .parsers.extract import extract_text_from_file
from .detection.scan import scan_text, serialize_findings
from .cache import ScanCache
def _should_include(path: str, include_exts, include_globs, exclude_globs):
    if include_exts and os.path.splitext(path)[1].lower() not in include_exts: return False
    return match_globs(path, include_globs, exclude_globs)
def collect_files(root_path: str, include_exts, include_globs, exclude_globs, threads=8,
                  ignore_globs=None, max_size_bytes=None, verbose=False) -> List[str]:
    include_exts = normalize_exts(include_exts)
    ignore_globs = (ignore_globs or [])
    paths = list(iter_files(root_path))
    selected: List[str] = []
    def check(p):
        try:
            if not _should_include(p, include_exts, include_globs, exclude_globs): return None
            if ignore_globs:
                from fnmatch import fnmatch
                norm=p.replace('\\','/')
                for pat in ignore_globs:
                    if fnmatch(norm, pat): return None
            if max_size_bytes is not None:
                try:
                    if os.path.getsize(p) > max_size_bytes: return None
                except Exception: return None
            return p
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=threads) as tp:
        for res in tp.map(check, paths):
            if res:
                selected.append(res)
                if verbose: print(res)
    return selected
def _scan_file(p, ent_min, ent_thr):
    t=extract_text_from_file(p)
    if t is None: return p, [], 'unreadable'
    return p, serialize_findings(scan_text(p,t,ent_min,ent_thr)), 'ok'
def scan_paths(paths: List[str], output_dir: str, formats: List[str], timestamp: bool, cache_file: str,
               entropy_min_len: int, entropy_thresh: float, workers: int | None,
               fail_on: str | None, scan_archives_flag: bool, verbose: bool, no_cache: bool=False):
    os.makedirs(output_dir, exist_ok=True)
    from .exporters.json_exporter import export_json
    from .exporters.csv_exporter import export_csv
    from .exporters.html_exporter import export_html
    from .exporters.sarif_exporter import export_sarif
    findings_all=[]
    cache=ScanCache(cache_file)
    to_scan=[]
    if no_cache:
        to_scan = list(paths)
    else:
        for p in paths:
            if cache.is_unchanged(p):
                cached = cache.get_findings(p)
                if cached:
                    findings_all.extend(cached)
                    if verbose: print(f"[CACHE] reused {len(cached)} findings from {p}")
                else:
                    if verbose: print(f"[CACHE] unchanged {p}, but no cached findings; queueing for scan")
                    to_scan.append(p)
            else:
                to_scan.append(p)
    if to_scan:
        with ProcessPoolExecutor(max_workers=workers or os.cpu_count() or 2) as pp:
            futs={pp.submit(_scan_file,p,entropy_min_len,entropy_thresh):p for p in to_scan}
            for fut in as_completed(futs):
                p=futs[fut]
                try:
                    _, f, st = fut.result()
                    if st=='ok':
                        if f: findings_all.extend(f)
                        if not no_cache:
                            cache.update(p, f)
                except Exception as e:
                    if verbose: print(f"[SKIP] {p} → exception {e}")
    if not no_cache:
        cache.save()
    import datetime as _dt
    stamp='_'+_dt.datetime.now().strftime('%Y%m%d_%H%M%S') if timestamp else ''
    base=os.path.join(output_dir,f'report{stamp}')
    if 'json' in formats: export_json(findings_all, base+'.json')
    if 'csv' in formats: export_csv(findings_all, base+'.csv')
    if 'html' in formats: export_html(findings_all, base+'.html')
    if 'sarif' in formats: export_sarif(findings_all, base+'.sarif')
    code=0
    sev_order={"Low":1,"Medium":2,"High":3}
    if fail_on:
        thr=sev_order[fail_on]
        worst=max([sev_order.get(f.get("severity","Low"),1) for f in findings_all] or [1])
        if worst>=thr: code=2
    return findings_all, code
