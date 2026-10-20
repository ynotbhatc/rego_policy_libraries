"""Dump a CIS workbook to JSON for gen_nginx.py / gen_fortigate.py: dump_workbook.py <workbook.xlsx> <out.json>."""
import sys, json, openpyxl
wb = openpyxl.load_workbook(sys.argv[1], read_only=True)
print("SHEETS", wb.sheetnames, file=sys.stderr)
recs = {}
for ws in wb.worksheets:
    name = ws.title
    if name in ("License","Overview"): continue
    rows = ws.iter_rows(values_only=True)
    hdr = [str(h).strip() if h else "" for h in next(rows)]
    for r in rows:
        d = dict(zip(hdr, r))
        rid = d.get("Recommendation #")
        if not rid: continue
        rid = str(rid).strip()
        e = recs.setdefault(rid, {"id": rid, "title": (d.get("Title") or "").strip(), "status": d.get("Assessment Status"), "sheets": [], "audit": d.get("Audit Procedure") or "", "section": d.get("Section #")})
        e["sheets"].append(name)
json.dump(list(recs.values()), open(sys.argv[2], "w"), indent=1)
print(len(recs), file=sys.stderr)
