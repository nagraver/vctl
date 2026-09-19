#!/usr/bin/env python3
"""Bounded macOS TUN test. Existing VPN remains connected; routes are restored."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vless_client.config import generate
from vless_client.storage import Store, atomic_json
from vless_client.runtime import core_binary, free_port, wait_ready, resolve_tun_state
from vless_client.macos import DNSLease

p=argparse.ArgumentParser();p.add_argument('--full',action='store_true');args=p.parse_args()
if os.geteuid()!=0:raise SystemExit('Run with sudo')
root=Path(__file__).resolve().parent.parent
profile=Path(os.environ.get('VCTL_HOME', str(root/'.local')))
state=json.loads((profile/'state.json').read_text())
node=next(iter(state['subscriptions'].values()))['nodes'][0]
state['selected']=node['id'];state['rules']=[]
with tempfile.TemporaryDirectory(prefix='vless-tun-test-',dir='/private/tmp') as directory:
 store=Store(directory);port=free_port();config=generate(resolve_tun_state(state),'tun',port)
 config['log']={'loglevel':'warning'}
 tun=config['inbounds'][-1]['settings']
 tun['autoOutboundsInterface']='en0'
 if not args.full:tun['autoSystemRoutingTable']=['104.16.133.229/32','2606:4700::6810:85e5/128','198.19.255.53/32']
 path=store.home/'config.json';atomic_json(path,config)
 dns=DNSLease(store)
 before=subprocess.run(['/sbin/route','-n','get','104.16.133.229'],capture_output=True,text=True).stdout
 log=open(store.home/'core.log','w')
 proc=subprocess.Popen([core_binary(),'run','-c',str(path)],stdout=log,stderr=log,start_new_session=True)
 # Independent deadline: survives the test driver's termination or lost tool connection.
 watchdog_code='''import os,sys,time,signal,subprocess
sys.path.insert(0,sys.argv[3])
from vless_client.storage import Store
from vless_client.macos import DNSLease
time.sleep(45)
pid=int(sys.argv[1]);expected=sys.argv[2]
cmd=subprocess.run(['/bin/ps','-p',str(pid),'-o','command='],capture_output=True,text=True).stdout
if expected in cmd:
 os.kill(pid,signal.SIGTERM)
 time.sleep(3)
 cmd=subprocess.run(['/bin/ps','-p',str(pid),'-o','command='],capture_output=True,text=True).stdout
 if expected in cmd:os.kill(pid,signal.SIGKILL)
DNSLease(Store(sys.argv[4])).restore()
'''
 watchdog=subprocess.Popen([sys.executable,'-c',watchdog_code,str(proc.pid),str(path),str(root),directory],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  wait_ready(proc,port)
  if args.full:dns.acquire()
  time.sleep(1)
  if proc.poll() is not None:raise RuntimeError('Xray exited during TUN setup')
  route=subprocess.run(['/sbin/route','-n','get','104.16.133.229'],capture_output=True,text=True).stdout
  iface=next((x.strip() for x in route.splitlines() if 'interface:' in x),'missing')
  print('TUN route:',iface,flush=True)
  if route==before:raise RuntimeError('Test route unchanged')
  for addr in ['104.16.133.229','[2606:4700::6810:85e5]']:
   url='https://cp.cloudflare.com/cdn-cgi/trace'
   result=subprocess.run(['curl','--silent','--noproxy','*','--max-time','8','--resolve',f'cp.cloudflare.com:443:{addr}',url],capture_output=True,text=True,timeout=10)
   print('IPv6' if '[' in addr else 'IPv4','HTTPS',result.returncode,'trace_ok', 'ip=' in result.stdout,flush=True)
   if result.returncode or 'ip=' not in result.stdout:
    if '[' not in addr:raise RuntimeError('TUN IPv4 HTTPS failed')
    baseline=subprocess.run(['curl','--silent','--noproxy','','--proxy',f'socks5h://127.0.0.1:{port}','--connect-to',f'cp.cloudflare.com:443:{addr}:443','--max-time','8',url],capture_output=True,text=True,timeout=10)
    print('IPv6 SOCKS baseline:',baseline.returncode,'trace_ok','ip=' in baseline.stdout,flush=True)
  dig=subprocess.run(['/usr/bin/dig','@198.19.255.53','example.com','A','+short','+time=3','+tries=1'],capture_output=True,text=True,timeout=5)
  print('UDP DNS:',dig.returncode==0 and bool(dig.stdout.strip()),flush=True)
  if args.full:
   r=subprocess.run(['curl','--silent','--noproxy','*','--max-time','8','--output','/dev/null','--write-out','%{http_code}','https://www.gstatic.com/generate_204'],capture_output=True,text=True,timeout=10)
   print('System DNS + HTTPS:',r.stdout,r.returncode,flush=True)
   if r.stdout!='204':raise RuntimeError('System DNS or HTTPS failed')
 finally:
  proc.terminate()
  try:proc.wait(timeout=5)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
  dns.restore()
  watchdog.terminate();watchdog.wait(timeout=5);log.close()
  after=subprocess.run(['/sbin/route','-n','get','104.16.133.229'],capture_output=True,text=True).stdout
  print('Previous route restored:', next((x.strip() for x in after.splitlines() if 'interface:' in x),'missing'),flush=True)
