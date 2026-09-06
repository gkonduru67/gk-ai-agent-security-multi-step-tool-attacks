#!/usr/bin/env python3
"""UTA fixture preflight v7.32: original SDK + normalized isolated fixtures.

Avoids the incomplete project-overlay design. Imports ToolSuite from the original
source tree, but passes an ASCII-safe isolated fixture directory. Produces a
manifest for PASS, gate FAIL, or environment/script failure.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, inspect, json, os, platform, shutil, sys, traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
V="UTA_FIXTURE_PREFLIGHT_v7.32"
WID="UTA_WEB_V732_001"; WM="UTA_WEB_MARKER_V732_7F3C91"
WOID="UTA_WEB_UNRELATED_V732_001"; WOM="UTA_WEB_UNRELATED_MARKER_V732_91BE20"
EID="UTA_EMAIL_V732_001"; EM="UTA_EMAIL_MARKER_V732_2A8D64"; ES="UTA_EMAIL_SUBJECT_V732"
EOID="UTA_EMAIL_UNRELATED_V732_001"; EOM="UTA_EMAIL_UNRELATED_MARKER_V732_C45A72"

def h(p):
 d=hashlib.sha256();
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): d.update(b)
 return d.hexdigest().upper()
def safe(x):
 if x is None or isinstance(x,(str,int,float,bool)): return x
 if isinstance(x,Path): return str(x)
 if isinstance(x,dict): return {str(k):safe(v) for k,v in x.items()}
 if isinstance(x,(list,tuple)): return [safe(v) for v in x]
 if hasattr(x,'__dict__'): return safe(vars(x))
 return repr(x)
def writej(p,x):
 p=Path(p)
 if p.exists(): raise FileExistsError(p)
 t=p.with_name(p.name+'.tmp'); t.write_text(json.dumps(safe(x),indent=2,ensure_ascii=True)+'\n',encoding='ascii',newline='\n'); os.replace(t,p)
def pages(x):
 if isinstance(x,dict) and isinstance(x.get('pages'),list): return x['pages']
 if isinstance(x,list): return x
 raise ValueError('Unsupported web schema')
def folders(x):
 if not isinstance(x,dict): raise ValueError('Unsupported mail schema')
 r={k:v for k,v in x.items() if isinstance(v,list)}
 if not r: raise ValueError('No email folders')
 return r
def messages(x): return [m for a in folders(x).values() for m in a if isinstance(m,dict)]
def cnt(a,i): return sum(isinstance(x,dict) and x.get('id')==i for x in a)
def check(i,p,e,o,c): return {'check_id':i,'passed':bool(p),'expected':safe(e),'observed':safe(o),'failure_classification':'' if p else c}
def norm_result(r):
 if isinstance(r,tuple) and len(r)>=3:return {'ok':bool(r[0]),'output':r[1],'error':r[2],'raw':safe(r)}
 if isinstance(r,dict):return {'ok':bool(r.get('ok',r.get('success',False))),'output':r.get('output',r.get('result','')),'error':r.get('error'),'raw':safe(r)}
 return {'ok':bool(getattr(r,'ok',getattr(r,'success',False))),'output':getattr(r,'output',getattr(r,'result','')),'error':getattr(r,'error',None),'raw':safe(r)}
def state(s):
 for n in ('state','_state','runtime_state','_runtime_state'):
  v=getattr(s,n,None)
  if v is not None:return v
def member(s,n): return s.get(n) if isinstance(s,dict) else getattr(s,n,None) if s is not None else None
def source(s):
 v=getattr(s,'last_source',None)
 if isinstance(v,str):return v
 v=member(state(s),'last_source'); return v if isinstance(v,str) else None
def call(s,n,a):
 errs=[]
 for mn in ('call','execute','invoke','run','call_tool','execute_tool'):
  m=getattr(s,mn,None)
  if not callable(m):continue
  for form,fn in [('kwargs',lambda:m(n,**a)),('dict',lambda:m(n,a)),('tool_args',lambda:m(tool_name=n,tool_args=a)),('name_arguments',lambda:m(name=n,arguments=a))]:
   try:return norm_result(fn()),{'method':mn,'signature':str(inspect.signature(m)),'form':form,'prior_type_errors':errs}
   except TypeError as e:errs.append({'method':mn,'form':form,'error':str(e)})
 raise RuntimeError('No ToolSuite call form matched: '+json.dumps(errs))
def construct(C,f):
 errs=[]
 for form,fn in [('positional_isolate',lambda:C(f,isolate_fs=True)),('keyword_isolate',lambda:C(fixtures_dir=f,isolate_fs=True)),('positional',lambda:C(f)),('keyword',lambda:C(fixtures_dir=f))]:
  try:return fn(),{'class':f'{C.__module__}.{C.__qualname__}','signature':str(inspect.signature(C)),'form':form,'prior_type_errors':errs}
  except TypeError as e:errs.append({'form':form,'error':str(e)})
 raise RuntimeError('No constructor matched: '+json.dumps(errs))
def manifest(out,root,status,classification,inputs,outputs,limitations):
 p=out/'uta_fixture_preflight_v7_32_freeze_manifest.json'
 files=[]
 for f in sorted(x for x in out.rglob('*') if x.is_file() and x!=p):files.append({'relative_path':f.relative_to(out).as_posix(),'size_bytes':f.stat().st_size,'sha256':h(f)})
 writej(p,{'schema':'UTA_FIXTURE_PREFLIGHT_FREEZE_V2','version':V,'created_utc':datetime.now(timezone.utc).isoformat(),'status':status,'classification':classification,'inputs':inputs,'artifacts':files,'runtime':{'python':sys.version,'platform':platform.platform()},'limitations':limitations})
 return p
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args()
 root=a.project_root.resolve();out=a.out_dir.resolve();src=root/'aicomp_sdk/fixtures';pw=src/'web_corpus.json';pm=src/'mail_seed.json'
 if out.exists():raise SystemExit(f'Refusing existing output: {out}')
 out.mkdir(parents=True);stage='INITIALIZE';inputs=[];limitations=['Direct ToolSuite fixture preflight only.','No model, agent, guardrail, predicate, breach, Sandbox, Gym, hosted, or production claim.','Isolated JSON was semantically normalized with ensure_ascii=True because SDK Path.read_text() used the Windows default codec.']
 try:
  stage='HASH_AND_COPY'; before={'web':h(pw),'mail':h(pm)}; inputs=[{'path':pw.relative_to(root).as_posix(),'sha256':before['web']},{'path':pm.relative_to(root).as_posix(),'sha256':before['mail']},{'path':Path(__file__).name,'sha256':h(Path(__file__).resolve())}]
  iso=out/'isolated_fixtures';shutil.copytree(src,iso);records=[]
  stage='NORMALIZE_ALL_JSON'
  for p in sorted(iso.rglob('*.json')):
   old=h(p);raw=p.read_bytes()
   try:o=json.loads(raw.decode('utf-8'))
   except UnicodeDecodeError:o=json.loads(raw.decode('utf-8-sig'))
   t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(o,ensure_ascii=True,separators=(',',':'))+'\n',encoding='ascii');os.replace(t,p);p.read_bytes().decode('ascii');records.append({'file':p.relative_to(out).as_posix(),'source_sha256':old,'normalized_sha256':h(p),'ascii_safe':True})
  iw=iso/'web_corpus.json';im=iso/'mail_seed.json';w=json.loads(iw.read_text(encoding='ascii'));m=json.loads(im.read_text(encoding='ascii'));pg=pages(w);fd=folders(m);inbox=next((x for x in ('inbox','Inbox','INBOX') if x in fd),sorted(fd)[0]);msgs=messages(m);checks=[]
  for arr,i in ((pg,WID),(pg,WOID),(msgs,EID),(msgs,EOID)):checks.append(check('ID_ABSENT_'+i,cnt(arr,i)==0,0,cnt(arr,i),'DUPLICATE_CONTROLLED_ID'))
  blob=json.dumps({'w':w,'m':m},ensure_ascii=True)
  for mk in (WM,WOM,EM,EOM):checks.append(check('MARKER_ABSENT_'+mk,blob.count(mk)==0,0,blob.count(mk),'CONTROLLED_MARKER_PREEXISTED'))
  if any(not x['passed'] for x in checks):raise RuntimeError('Controlled ID or marker pre-existed')
  pg.extend([{'id':WID,'title':'UTA Controlled v7.32','content':'Controlled '+WM},{'id':WOID,'title':'UTA Unrelated v7.32','content':'Unrelated '+WOM}]);fd[inbox].extend([{'id':EID,'from':'controlled@example.invalid','subject':ES,'body':'Controlled '+EM},{'id':EOID,'from':'unrelated@example.invalid','subject':'UTA_EMAIL_UNRELATED_SUBJECT_V732','body':'Unrelated '+EOM}]);iw.write_text(json.dumps(w,ensure_ascii=True,separators=(',',':'))+'\n',encoding='ascii');im.write_text(json.dumps(m,ensure_ascii=True,separators=(',',':'))+'\n',encoding='ascii')
  stage='IMPORT_ORIGINAL_TOOLSUITE';sys.path.insert(0,str(root));mod=importlib.import_module('aicomp_sdk.core.tools.suite');C=getattr(mod,'ToolSuite')
  stage='CONSTRUCT_TOOLSUITE';suite,ctor=construct(C,iso)
  st=state(suite);checks.extend([check('WEB_PRESENT_AFTER_INIT',cnt(pages(member(st,'web')),WID)==1,1,cnt(pages(member(st,'web')),WID),'FIXTURE_RECORD_NOT_LOADED'),check('EMAIL_PRESENT_AFTER_INIT',cnt(messages(member(st,'mail')),EID)==1,1,cnt(messages(member(st,'mail')),EID),'FIXTURE_RECORD_NOT_LOADED')])
  calls={}
  def do(label,name,args):
   r,adapter=call(suite,name,args);calls[label]={'tool':name,'arguments':args,'result':r,'source':source(suite),'adapter':adapter};return calls[label]
  stage='CALL_TOOLS';we=do('web_exact','web.open',{'id':WID});wo=do('web_other','web.open',{'id':WOID});wx=do('web_missing','web.open',{'id':'UTA_WEB_MISSING_V732_404'});ee=do('email_exact','email.read',{'id':EID});eo=do('email_other','email.read',{'id':EOID});ex=do('email_missing','email.read',{'id':'UTA_EMAIL_MISSING_V732_404'})
  txt=lambda r:r['result']['output'] if isinstance(r['result']['output'],str) else json.dumps(safe(r['result']['output']))
  checks += [check('WEB_EXACT',we['result']['ok'] and WM in txt(we) and we['source']=='web',{'ok':True,'marker':WM,'source':'web'},we,'SOURCE_READ_FAILED'),check('WEB_OTHER',wo['result']['ok'] and WOM in txt(wo) and WM not in txt(wo),WOM,txt(wo),'WRONG_SOURCE_RECORD_SELECTED'),check('WEB_MISSING',not wx['result']['ok'] and wx['result']['error']=='not_found','not_found',wx['result'],'SOURCE_RECORD_NOT_FOUND'),check('EMAIL_EXACT',ee['result']['ok'] and EM in txt(ee) and ES in txt(ee) and ee['source']=='email',{'ok':True,'marker':EM,'subject':ES,'source':'email'},ee,'SOURCE_READ_FAILED'),check('EMAIL_OTHER',eo['result']['ok'] and EOM in txt(eo) and EM not in txt(eo),EOM,txt(eo),'WRONG_SOURCE_RECORD_SELECTED'),check('EMAIL_MISSING',not ex['result']['ok'] and ex['result']['error']=='not_found','not_found',ex['result'],'SOURCE_RECORD_NOT_FOUND')]
  after={'web':h(pw),'mail':h(pm)};checks += [check('PACKAGED_WEB_UNCHANGED',after['web']==before['web'],before['web'],after['web'],'PACKAGED_FIXTURE_MODIFIED'),check('PACKAGED_MAIL_UNCHANGED',after['mail']==before['mail'],before['mail'],after['mail'],'PACKAGED_FIXTURE_MODIFIED')]
  failed=[x for x in checks if not x['passed']];status='PASS' if not failed else 'FAIL';classification='FIXTURE_PREFLIGHT_PASS' if not failed else failed[0]['failure_classification'];rawp=out/'uta_fixture_preflight_v7_32_raw.json';csvp=out/'uta_fixture_preflight_v7_32_summary.csv';writej(rawp,{'schema':'UTA_FIXTURE_PREFLIGHT_V2','version':V,'status':status,'classification':classification,'normalization_records':records,'constructor':ctor,'calls':calls,'checks':checks,'summary':{'checks':len(checks),'passed':len(checks)-len(failed),'failed':len(failed)},'packaged_before':before,'packaged_after':after,'limitations':limitations})
  with csvp.open('x',encoding='utf-8',newline='') as f:
   wr=csv.DictWriter(f,fieldnames=['check_id','passed','expected','observed','failure_classification']);wr.writeheader();[wr.writerow({'check_id':x['check_id'],'passed':x['passed'],'expected':json.dumps(x['expected']),'observed':json.dumps(x['observed']),'failure_classification':x['failure_classification']}) for x in checks]
  mp=manifest(out,root,status,classification,inputs,[rawp,csvp],limitations);print(f'Experiment: {V}\nStatus: {status}\nClassification: {classification}\nChecks: {len(checks)}\nPassed: {len(checks)-len(failed)}\nFailed: {len(failed)}\nFreeze manifest: {mp}\nFreeze manifest SHA256: {h(mp)}');return 0 if not failed else 2
 except Exception as e:
  diag=out/'uta_fixture_preflight_v7_32_failure.json';writej(diag,{'version':V,'status':'SCRIPT_OR_ENVIRONMENT_FAILURE','stage':stage,'exception_type':type(e).__name__,'exception':str(e),'traceback':traceback.format_exc(),'scientific_result':None,'limitations':limitations});mp=manifest(out,root,'SCRIPT_OR_ENVIRONMENT_FAILURE',stage,inputs,[],limitations);print(f'Failed stage: {stage}\nDiagnostic: {diag}\nFailure manifest: {mp}\nFailure manifest SHA256: {h(mp)}',file=sys.stderr);return 3
if __name__=='__main__':raise SystemExit(main())
