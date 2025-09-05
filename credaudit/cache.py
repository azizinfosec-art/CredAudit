import os, json
class ScanCache:
    def __init__(self, cache_path: str):
        self.cache_path=cache_path
        self._data={}
        try:
            if os.path.exists(cache_path):
                with open(cache_path,'r',encoding='utf-8') as f:
                    self._data=json.load(f)
        except Exception:
            self._data={}
    def _key(self, path:str)->str: return os.path.abspath(path)
    def is_unchanged(self, path: str) -> bool:
        try:
            st=os.stat(path); rec=self._data.get(self._key(path))
            return bool(rec and rec.get("mtime")==st.st_mtime and rec.get("size")==st.st_size)
        except Exception: return False
    def get_findings(self, path:str):
        rec=self._data.get(self._key(path)) or {}; return rec.get("findings", [])
    def update(self, path: str, findings):
        try:
            st=os.stat(path); self._data[self._key(path)]={"mtime":st.st_mtime, "size":st.st_size, "findings": findings}
        except Exception: pass
    def save(self):
        try:
            with open(self.cache_path,'w',encoding='utf-8') as f: json.dump(self._data,f,ensure_ascii=False,indent=2)
        except Exception: pass
