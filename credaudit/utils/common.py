import os, fnmatch
REDACTION_MASK = "****"
def normalize_exts(exts):
    if not exts: return []
    out=[]
    for e in exts:
        e=e.strip()
        if not e: continue
        if not e.startswith('.'): e='.'+e
        out.append(e.lower())
    return out
def match_globs(path, include_globs, exclude_globs):
    norm = path.replace('\\','/')
    if exclude_globs:
        for pat in exclude_globs:
            if fnmatch.fnmatch(norm, pat): return False
    if include_globs:
        for pat in include_globs:
            if fnmatch.fnmatch(norm, pat): return True
        return False
    return True
def redact_secret(s: str) -> str:
    value = str(s or "")
    if len(value) <= 4: return REDACTION_MASK
    if len(value) <= 8: return f"{value[:1]}{REDACTION_MASK}{value[-1:]}"
    if len(value) <= 16: return f"{value[:2]}{REDACTION_MASK}{value[-2:]}"
    return f"{value[:4]}{REDACTION_MASK}{value[-4:]}"
def redact_finding_record(record: dict) -> dict:
    out = dict(record) if isinstance(record, dict) else {}
    raw = str(out.get("match", "") or "")
    redacted = str(out.get("redacted", "") or "")
    if raw and (not redacted or redacted == raw):
        redacted = redact_secret(raw)
    if not redacted:
        redacted = REDACTION_MASK
    context = str(out.get("context", "") or "")
    if raw and context:
        context = context.replace(raw, redacted)
    out["redacted"] = redacted
    out["match"] = redacted
    out["context"] = context
    return out
def redact_finding_records(records):
    return [redact_finding_record(r) for r in records]
def _dir_matches_glob(path: str, root_path: str, pattern: str) -> bool:
    pat = str(pattern or "").replace("\\", "/").strip()
    if not pat:
        return False
    norm = os.path.abspath(path).replace("\\", "/")
    try:
        rel = os.path.relpath(path, root_path).replace("\\", "/")
    except Exception:
        rel = norm
    candidates = [norm, norm + "/", rel, rel + "/"]
    patterns = [pat]
    if pat.startswith("**/"):
        patterns.append(pat[3:])
    for active_pat in patterns:
        if any(fnmatch.fnmatch(candidate, active_pat) for candidate in candidates):
            return True
        if active_pat.endswith("/**"):
            base = active_pat[:-3].rstrip("/")
            if any(fnmatch.fnmatch(candidate.rstrip("/"), base) for candidate in candidates):
                return True
    return False


def iter_files(root_path: str, prune_globs=None):
    if os.path.isfile(root_path):
        yield os.path.abspath(root_path); return
    root_abs = os.path.abspath(root_path)
    prune_globs = prune_globs or []
    for dirpath, dirnames, filenames in os.walk(root_abs):
        if prune_globs:
            dirnames[:] = [
                dirname for dirname in dirnames
                if not any(
                    _dir_matches_glob(os.path.join(dirpath, dirname), root_abs, pat)
                    for pat in prune_globs
                )
            ]
        for fn in filenames:
            try:
                yield os.path.abspath(os.path.join(dirpath, fn))
            except Exception:
                continue
def load_ignore_file(path: str):
    pats=[]
    if not path or not os.path.exists(path): return pats
    try:
        with open(path,'r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith('#'): continue
                pats.append(line)
    except Exception:
        return pats
    return pats
