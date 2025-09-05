import os, fnmatch
REDACTION_MASK = "**********"
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
    if len(s) <= 8: return REDACTION_MASK
    return f"{s[:4]}{REDACTION_MASK}{s[-4:]}"
def iter_files(root_path: str):
    if os.path.isfile(root_path):
        yield os.path.abspath(root_path); return
    for dirpath, dirnames, filenames in os.walk(root_path):
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
