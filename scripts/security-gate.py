import json,glob,os,sys
root=sys.argv[1]; fail=False; messages=[]
order={'INFO':0,'WARNING':1,'LOW':1,'MEDIUM':2,'ERROR':3,'HIGH':3,'CRITICAL':4}
threshold=order.get(os.getenv('FAIL_ON_SAST','ERROR').upper(),3)
for p in glob.glob(root+'/**/sast-normalized.json',recursive=True):
  for x in json.load(open(p)):
    if order.get(str(x.get('severity','')).upper(),0)>=threshold: fail=True; messages.append('SAST: '+str(x.get('rule')))
zthr=os.getenv('FAIL_ON_ZAP_RISK','High').lower()
for p in glob.glob(root+'/**/dast-normalized.json',recursive=True):
  for x in json.load(open(p)):
    risk=str(x.get('risk','')).lower()
    if zthr in risk or ('high' in risk and zthr in ('medium','low')): fail=True; messages.append('DAST: '+str(x.get('name')))
summary=os.getenv('GITHUB_STEP_SUMMARY')
if summary:
  with open(summary,'a') as f: f.write('# Security gate\n\n' + ('\n'.join('- '+m for m in messages) if messages else 'No blocking findings.')+'\n')
if fail: sys.exit('Security gate failed')
