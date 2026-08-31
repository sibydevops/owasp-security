import json,sys,os
src,out=sys.argv[1:3]
data=json.load(open(src,encoding='utf-8'))
rows=[]
for x in data.get('results',[]):
    sev=x.get('extra',{}).get('severity','UNKNOWN')
    msg=x.get('extra',{}).get('message','')
    meta=x.get('extra',{}).get('metadata',{})
    rows.append({'tool':'Semgrep CE','rule':x.get('check_id'),'severity':sev,'path':x.get('path'),'message':msg,'cwe':meta.get('cwe'),'owasp':meta.get('owasp')})
os.makedirs(out,exist_ok=True)
json.dump(rows,open(os.path.join(out,'sast-normalized.json'),'w'),indent=2)
with open(os.path.join(out,'sast-summary.md'),'w') as f:
    f.write('# SAST summary\n\nFindings: %d\n' % len(rows))
