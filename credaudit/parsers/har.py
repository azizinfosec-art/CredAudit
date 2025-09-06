import json, base64
from typing import Iterator, Tuple, Optional

TEXTUAL = (
    "text/html",
    "text/plain",
    "application/json",
    "application/javascript",
    "text/javascript",
)

def _is_textual(mime: Optional[str]) -> bool:
    if not mime:
        return True
    m = mime.split(";", 1)[0].strip().lower()
    return (
        m in TEXTUAL or m.startswith("text/") or m.endswith("+json") or ("json" in m)
    )

def _decode_text(text: Optional[str], encoding: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    if (encoding or "").lower() == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="ignore")
        except Exception:
            return None
    return text

def iter_har_texts(path: str, include_requests: bool = True, include_responses: bool = True,
                   max_body_bytes: int = 2 * 1024 * 1024) -> Iterator[Tuple[str, str]]:
    """Yield (virtual_file_id, text) pairs from a HAR file.

    virtual_file_id will be like '<url>#response' or '<url>#request'.
    Only textual MIME types are returned, and bodies larger than max_body_bytes are skipped.
    """
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
    entries = (data.get('log') or {}).get('entries') or []
    for e in entries:
        url = ((e.get('request') or {}).get('url')) or ''
        if include_responses:
            resp = (e.get('response') or {})
            cont = (resp.get('content') or {})
            mime = cont.get('mimeType')
            txt = _decode_text(cont.get('text'), cont.get('encoding'))
            if txt and _is_textual(mime):
                if len(txt.encode('utf-8', 'ignore')) <= max_body_bytes:
                    yield f"{url}#response", txt
        if include_requests:
            req = (e.get('request') or {})
            post = (req.get('postData') or {})
            mime = post.get('mimeType') or (req.get('headers') or [])
            txt = post.get('text')
            # HAR request postData.text is plain text by spec; some tools base64 it and set encoding
            enc = post.get('encoding')
            txt = _decode_text(txt, enc)
            if txt:
                # Determine if textual: prefer postData.mimeType; if absent, treat as textual by default
                m = (post.get('mimeType') or '').split(';',1)[0].strip().lower()
                if not m:
                    ok = True
                else:
                    ok = _is_textual(m)
                if ok and len(txt.encode('utf-8', 'ignore')) <= max_body_bytes:
                    yield f"{url}#request", txt

