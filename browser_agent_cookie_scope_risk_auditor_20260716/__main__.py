import argparse,json,datetime
def audit(cookies):
    risks=[]
    for c in cookies:
        name=c.get('name',''); dom=c.get('domain',''); flags=[]
        if dom.startswith('.') or dom.count('.')<=1: flags.append('broad-domain')
        if not c.get('httpOnly',False): flags.append('not-httpOnly')
        if not c.get('secure',False): flags.append('not-secure')
        if c.get('sameSite','').lower() in ('none','no_restriction',''): flags.append('weak-sameSite')
        if any(x in name.lower() for x in ['session','token','auth']): flags.append('auth-like-name')
        if flags: risks.append({'name':name,'domain':dom,'flags':flags,'severity':'high' if 'auth-like-name' in flags and len(flags)>1 else 'medium'})
    return {'cookie_count':len(cookies),'risky_count':len(risks),'risks':risks}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Audit browser-agent cookie exports before sharing them with automation or LLM agents.'); ap.add_argument('cookies_json')
    ns=ap.parse_args(argv); data=json.load(open(ns.cookies_json,encoding='utf-8')); print(json.dumps(audit(data if isinstance(data,list) else data.get('cookies',[])),indent=2))
if __name__=='__main__': main()
