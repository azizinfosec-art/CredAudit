import os
TEXT_EXTS={'.txt','.json','.env','.log','.cfg','.ini','.yaml','.yml','.py','.js','.toml'}
KEYWORDS = {"password","pass","pwd","secret","apikey","api_key","api-key","token"}
def read_text_with_fallback(p):
    for enc in ['utf-8','utf-16','latin-1']:
        try:
            with open(p,'r',encoding=enc,errors='ignore') as f: return f.read()
        except Exception: pass
    return None
def extract_text_from_file(p):
    ext=os.path.splitext(p)[1].lower()
    try:
        if ext in TEXT_EXTS: 
            return read_text_with_fallback(p)
        if ext=='.pdf':
            try:
                from pdfminer.high_level import extract_text
                return extract_text(p)
            except Exception:
                return None
        if ext=='.docx':
            try:
                from docx import Document
                return "\n".join([x.text for x in Document(p).paragraphs])
            except Exception:
                return None
        if ext=='.xlsx':
            try:
                import openpyxl
                wb=openpyxl.load_workbook(p,read_only=True,data_only=True); o=[]
                for ws in wb.worksheets:
                    for row in ws.iter_rows(values_only=True):
                        cells=[str(v).strip() for v in row if v is not None]
                        if not cells: 
                            continue
                        if len(cells)>=2:
                            k=cells[0].strip().lower()
                            k_norm=k.replace(' ','').replace('-','_')
                            if k in KEYWORDS or k_norm in KEYWORDS:
                                o.append(f"{cells[0]}: {cells[1]}")
                                continue
                        o.append(" ".join(cells))
                return "\n".join(o)
            except Exception:
                return None
    except Exception:
        return None
    return None
