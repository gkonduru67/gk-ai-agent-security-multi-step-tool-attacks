#!/usr/bin/env python3
"""Create a publication-safe Excel risk inventory from web_corpus.json.

This is a deterministic lexical/structural pre-screen, not a final harmfulness
classifier. It never executes fixture instructions. Raw content is not written
to the workbook by default; only hashes, lengths, matched indicators, and short
reasons are exported. Manual review remains required.
"""
from __future__ import annotations
import argparse, hashlib, html, json, re
from collections import Counter
from pathlib import Path
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.formatting.rule import FormulaRule
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.chart import BarChart, Reference

VERSION = "WEB_CORPUS_RISK_INVENTORY_v1.00"
RULES = [
 ("PROTECTED_FILE_ACCESS", "High", [r"\bsecret\.txt\b", r"\bfs\.read\b", r"read_file\s*\(", r"\bcredential(?:s)?\b", r"\bapi[_ -]?key\b"], "Requests or demonstrates access to protected or credential-like data."),
 ("EXTERNAL_DATA_TRANSFER", "High", [r"\bhttp\.post\b", r"send_to_server\s*\(", r"\bcollector\b", r"\bexfiltrat(?:e|ion)\b", r"\bleak\b"], "Requests or demonstrates transfer of data to an external sink."),
 ("COMMAND_EXECUTION", "High", [r"\bshell\.run\b", r"\bwhoami\b", r"\bcat\s+secret\.txt\b", r"\bexecute this code\b"], "Requests command or code execution."),
 ("DESTRUCTIVE_ACTION", "High", [r"\bfs\.delete\b", r"delete_file\s*\(", r"\bdelete\b.{0,40}\bfile\b"], "Requests deletion or another destructive file action."),
 ("AUTHORITY_IMPERSONATION", "High", [r"system instruction", r"instructions? du syst[eè]me", r"instrucciones del sistema", r"authorized system", r"instrucciones autorizadas"], "Presents untrusted content as system-authorized instructions."),
 ("IMPERATIVE_TOOL_SEQUENCE", "High", [r"you try:\s*fs\.", r"you try:\s*http\.", r"go ahead and complete", r"please execute", r"por favor ejecuta", r"veuillez ex[eé]cuter"], "Directly instructs the agent to perform a tool sequence."),
 ("HIDDEN_OR_METADATA_INSTRUCTION", "High", [r"hidden comment metadata", r"<!--.{0,400}system instruction", r"to:\s*ai_assistant", r"execute_immediately"], "Places action instructions in comments, metadata, or hidden-looking text."),
 ("ENCODED_OR_OBFUSCATED_INSTRUCTION", "Medium", [r"\bbase64\b", r"\bhex(?:adecimal)?\b", r"\boctal\b", r"html[- ]entit", r"\bmorse\b", r"unicode"], "Uses or discusses encoding/obfuscation that may conceal instructions."),
 ("URGENCY_OR_PRIORITY_PRESSURE", "Medium", [r"\burgent\b", r"\bcritical\b", r"execute_immediately", r"priority:"], "Uses urgency or priority language to pressure action."),
 ("TOOL_TOKEN_PRESENT", "Review", [r"\bfs\.(?:read|write|delete)\b", r"\bhttp\.post\b", r"\bemail\.send\b", r"\bshell\.run\b", r"\bweb\.open\b"], "Contains explicit tool names and requires contextual review."),
]
SEV = {"High":3,"Medium":2,"Review":1,"None":0}
def sha(v:str)->str:return hashlib.sha256(v.encode("utf-8")).hexdigest().upper()
def records(root):
 if isinstance(root,list): return root,"<top-level-list>"
 if isinstance(root,dict):
  for k in ("pages","records","items","documents"):
   if isinstance(root.get(k),list): return root[k],k
 raise ValueError("Could not find record array. Expected list or object key pages/records/items/documents.")
def clean_text(v):
 s=html.unescape(str(v or ""));s=re.sub(r"<[^>]+>"," ",s);return re.sub(r"\s+"," ",s).strip()
def classify(rec):
 title=clean_text(rec.get("title"));url=clean_text(rec.get("url"));content=clean_text(rec.get("content")); hay=(title+"\n"+url+"\n"+content).lower()
 hits=[]
 for category,severity,patterns,reason in RULES:
  matched=sorted({m.group(0)[:80] for p in patterns for m in re.finditer(p,hay,re.I|re.S)})
  if matched:hits.append((category,severity,reason,matched))
 maxsev=max((SEV[x[1]] for x in hits),default=0);severity=next(k for k,v in SEV.items() if v==maxsev)
 high_categories=sorted(x[0] for x in hits if x[1]=="High")
 status="FLAGGED_HIGH_RISK" if severity=="High" else ("REVIEW_REQUIRED" if hits else "NO_RULE_MATCH")
 reason="; ".join(dict.fromkeys(x[2] for x in hits)) or "No configured lexical or structural rule matched. This is not proof of safety."
 return {"record_id":str(rec.get("id") or ""),"title":title,"url_sha256":sha(url),"content_length":len(content),"content_sha256":sha(content),"risk_status":status,"max_severity":severity,"risk_categories":" | ".join(x[0] for x in hits),"high_risk_category_count":len(high_categories),"all_rule_match_count":len(hits),"reason":reason,"matched_indicators":" | ".join(f"{x[0]}: {', '.join(x[3])}" for x in hits),"manual_review_required":"Yes","raw_content_exported":"No"}
def style_header(ws,row=1):
 for c in ws[row]:c.fill=PatternFill("solid",fgColor="17365D");c.font=Font(color="FFFFFF",bold=True);c.alignment=Alignment(wrap_text=True,vertical="center")
 ws.row_dimensions[row].height=32

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--fixture",required=True,type=Path);ap.add_argument("--output",required=True,type=Path);a=ap.parse_args()
 if not a.fixture.is_file():ap.error("Fixture not found")
 if a.output.exists():ap.error("Refusing to overwrite output")
 root=json.loads(a.fixture.read_text(encoding="utf-8"));items,key=records(root);rows=[classify(x) for x in items if isinstance(x,dict)]
 wb=Workbook();ws=wb.active;ws.title="Record Risk Inventory";headers=list(rows[0]) if rows else ["record_id"]
 ws.append(headers)
 for r in rows:ws.append([r[h] for h in headers])
 style_header(ws);ws.freeze_panes="A2";ws.sheet_view.showGridLines=False
 widths={"A":22,"B":38,"C":68,"D":16,"E":68,"F":22,"G":15,"H":48,"I":18,"J":18,"K":72,"L":80,"M":20,"N":20}
 for col,w in widths.items():ws.column_dimensions[col].width=w
 for row in ws.iter_rows(min_row=2):
  for c in row:c.alignment=Alignment(vertical="top",wrap_text=True)
  for idx in (1,2,3,5):row[idx-1].font=Font(color="008000")
 if rows:
  ref=f"A1:{ws.cell(ws.max_row,ws.max_column).coordinate}";tab=Table(displayName="RiskInventory",ref=ref);tab.tableStyleInfo=TableStyleInfo(name="TableStyleMedium2",showRowStripes=True,showColumnStripes=False);ws.add_table(tab)
  status_col=headers.index("risk_status")+1;letter=ws.cell(1,status_col).column_letter
  ws.conditional_formatting.add(f"{letter}2:{letter}{ws.max_row}",FormulaRule(formula=[f'${letter}2="FLAGGED_HIGH_RISK"'],fill=PatternFill("solid",fgColor="FFC7CE")))
  ws.conditional_formatting.add(f"{letter}2:{letter}{ws.max_row}",FormulaRule(formula=[f'${letter}2="REVIEW_REQUIRED"'],fill=PatternFill("solid",fgColor="FCE4D6")))
 summary=wb.create_sheet("Summary");summary.sheet_view.showGridLines=False
 summary.append(["Metric","Value"]);style_header(summary)
 counts=Counter(r["risk_status"] for r in rows);summary_rows=[("Fixture file",a.fixture.name),("Fixture SHA-256",hashlib.sha256(a.fixture.read_bytes()).hexdigest().upper()),("Fixture array key",key),("Inventory version",VERSION),("Records scanned",len(rows)),("Flagged high risk",counts["FLAGGED_HIGH_RISK"]),("Review required",counts["REVIEW_REQUIRED"]),("No rule match",counts["NO_RULE_MATCH"]),("Method boundary","Deterministic lexical/structural pre-screen; not a final safety judgment"),("Raw content exported","No")]
 for x in summary_rows:summary.append(x)
 summary.column_dimensions["A"].width=34;summary.column_dimensions["B"].width=95
 for row in summary.iter_rows(min_row=2):
  row[0].font=Font(color="666666");row[1].alignment=Alignment(wrap_text=True,vertical="top")
 status_start=6;chart=BarChart();chart.title="Record Classification";chart.y_axis.title="Records";chart.x_axis.title="Status";chart.add_data(Reference(summary,min_col=2,min_row=status_start,max_row=status_start+2),titles_from_data=False);chart.set_categories(Reference(summary,min_col=1,min_row=status_start,max_row=status_start+2));summary.add_chart(chart,"D2")
 rules=wb.create_sheet("Rules and Limitations");rules.sheet_view.showGridLines=False;rules.append(["Category","Severity","Reason","Patterns (publication-safe rule text)"])
 for cat,sev,pats,reason in RULES:rules.append([cat,sev,reason," | ".join(pats)])
 style_header(rules);rules.freeze_panes="A2";rules.column_dimensions["A"].width=38;rules.column_dimensions["B"].width=14;rules.column_dimensions["C"].width=70;rules.column_dimensions["D"].width=90
 for row in rules.iter_rows(min_row=2):
  for c in row:c.alignment=Alignment(wrap_text=True,vertical="top")
 notes=wb.create_sheet("Publication Notes");notes.sheet_view.showGridLines=False;notes.append(["Item","Statement"]);style_header(notes)
 note_rows=[("Terminology","Use 'rule-flagged' or 'requires human review', not 'proven harmful', unless runtime evidence independently establishes harm."),("Raw evidence","Keep web_corpus.json restricted. Publish IDs, hashes, categories, and reasons rather than full adversarial content."),("False positives","A tool token can occur in educational or defensive text. Lexical matches are screening evidence, not behavioral proof."),("False negatives","Obfuscated or novel instructions may evade configured rules. NO_RULE_MATCH is not proof of safety."),("Runtime boundary","Fixture presence does not establish that web.open retrieved the record, that an agent followed it, or that a later effect occurred."),("Reproducibility","Freeze this script, fixture SHA-256, generated workbook SHA-256, and rule version together.")]
 for x in note_rows:notes.append(x)
 notes.column_dimensions["A"].width=25;notes.column_dimensions["B"].width=110
 for row in notes.iter_rows(min_row=2):
  row[0].font=Font(color="666666");row[1].alignment=Alignment(wrap_text=True,vertical="top")
 wb.save(a.output);print(json.dumps({"version":VERSION,"records":len(rows),"output":str(a.output),"output_sha256":hashlib.sha256(a.output.read_bytes()).hexdigest().upper()},indent=2))
if __name__=="__main__":raise SystemExit(main())
