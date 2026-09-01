#!/usr/bin/env python3
import json, os, sys
from collections import Counter
from pathlib import Path

SAST={"INFO":1,"WARNING":2,"ERROR":3,"NONE":999}
ZAP={"INFORMATIONAL":0,"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"NONE":999}

def norm(v): return str(v or "").strip().upper()
def find(root,name):
    p=root/name
    if p.is_file(): return p
    return next(iter(sorted(root.rglob(name))),None)
def load(p):
    try: d=json.loads(p.read_text(encoding="utf-8"))
    except Exception as e: raise RuntimeError(f"Cannot parse {p}: {e}") from e
    if not isinstance(d,dict): raise RuntimeError(f"{p} must contain a JSON object")
    return d
def esc(v): return str(v).replace('%','%25').replace('\r','%0D').replace('\n','%0A')
def error(msg,file="",line=""):
    props=[]
    if file: props.append(f"file={esc(file).replace(':','%3A').replace(',','%2C')}")
    if str(line).isdigit(): props.append(f"line={line}")
    print(f"::error{(' '+','.join(props)) if props else ''}::{esc(msg)}")
def risk(a):
    r=norm(a.get('riskdesc') or a.get('risk') or a.get('riskcode'))
    if 'HIGH' in r or r=='3': return 'HIGH'
    if 'MEDIUM' in r or r=='2': return 'MEDIUM'
    if 'LOW' in r or r=='1': return 'LOW'
    return 'INFORMATIONAL'

def main():
    if len(sys.argv)!=2: print(f"Usage: {Path(sys.argv[0]).name} REPORT_DIR",file=sys.stderr); return 2
    root=Path(sys.argv[1]); st=norm(os.getenv('FAIL_ON_SAST','ERROR')); zt=norm(os.getenv('FAIL_ON_ZAP_RISK','HIGH'))
    if not root.is_dir(): error(f"Report directory missing: {root}"); return 2
    if st not in SAST or zt not in ZAP: error(f"Invalid thresholds: SAST={st}, ZAP={zt}"); return 2
    sp=find(root,'semgrep.json')
    if not sp: error('Mandatory semgrep.json is missing'); return 2
    try: sr=load(sp)
    except RuntimeError as e: error(str(e)); return 2
    results=sr.get('results',[])
    if not isinstance(results,list): error("semgrep results must be an array"); return 2
    sc=Counter(); sb=[]
    for x in results:
        if not isinstance(x,dict): continue
        ex=x.get('extra',{}) if isinstance(x.get('extra',{}),dict) else {}
        sev=norm(ex.get('severity','INFO')); sev=sev if sev in ('INFO','WARNING','ERROR') else 'INFO'; sc[sev]+=1
        if st!='NONE' and SAST[sev]>=SAST[st]:
            start=x.get('start',{}) if isinstance(x.get('start',{}),dict) else {}
            sb.append((sev,str(x.get('check_id','unknown-rule')),str(x.get('path','unknown-file')),start.get('line',''),str(ex.get('message','Semgrep finding'))))
    zp=find(root,'zap.json'); zc=Counter(); zb=[]
    if zp:
        try: zr=load(zp)
        except RuntimeError as e: error(str(e)); return 2
        for site in zr.get('site',[]) if isinstance(zr.get('site',[]),list) else []:
            if not isinstance(site,dict): continue
            name=str(site.get('@name') or site.get('name') or 'unknown-site')
            for a in site.get('alerts',[]) if isinstance(site.get('alerts',[]),list) else []:
                if not isinstance(a,dict): continue
                r=risk(a); zc[r]+=1
                if zt!='NONE' and ZAP[r]>=ZAP[zt]: zb.append((r,str(a.get('alert') or a.get('name') or 'Unknown alert'),name))
    print(f"SAST counts: ERROR={sc['ERROR']} WARNING={sc['WARNING']} INFO={sc['INFO']}")
    print(f"ZAP counts: HIGH={zc['HIGH']} MEDIUM={zc['MEDIUM']} LOW={zc['LOW']} INFORMATIONAL={zc['INFORMATIONAL']}" if zp else 'ZAP report not present')
    for sev,rule,file,line,msg in sb: print(f"[{sev}] {rule} at {file}:{line}: {msg}"); error(f"[{sev}] {rule}: {msg}",file,line)
    for r,name,site in zb: print(f"[{r}] {name} on {site}"); error(f"[{r}] ZAP {name} on {site}")
    summary=os.getenv('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary,'a',encoding='utf-8') as f: f.write(f"## OWASP policy gate\n\n- SAST blocking: {len(sb)}\n- DAST blocking: {len(zb)}\n- Result: {'Failed' if sb or zb else 'Passed'}\n")
    if sb or zb: print(f"Security gate failed: {len(sb)} SAST, {len(zb)} DAST blocking finding(s)."); return 1
    print('Security gate passed'); return 0
if __name__=='__main__': raise SystemExit(main())
