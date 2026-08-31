import json,sys,os
src,out=sys.argv[1:3]
data=json.load(open(src,encoding='utf-8')); rows=[]
map_wstg={'10020':'WSTG-CONF','10021':'WSTG-CONF','40012':'WSTG-INPV','40014':'WSTG-INPV','40018':'WSTG-INPV','40019':'WSTG-INPV'}
for site in data.get('site',[]):
  for a in site.get('alerts',[]):
    pid=str(a.get('pluginid',''))
    rows.append({'tool':'OWASP ZAP','plugin_id':pid,'name':a.get('alert'),'risk':a.get('riskdesc'),'count':a.get('count'),'wstg':map_wstg.get(pid,'WSTG review required'),'asvs':'ASVS control mapping requires validation'})
os.makedirs(out,exist_ok=True); json.dump(rows,open(os.path.join(out,'dast-normalized.json'),'w'),indent=2)
