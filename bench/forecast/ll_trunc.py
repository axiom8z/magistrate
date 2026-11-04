# Local only: does llama3.2:3b silently truncate an oversize tool result at the default context? Talks to 127.0.0.1:11434; unloads afterwards.
import json, urllib.request, urllib.error, time
BASE="http://127.0.0.1:11434"
big=("Lorem ipsum dolor sit amet consectetur adipiscing elit. "*600)[:27777]
msgs=[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Summarise the tool result in one line."},
      {"role":"assistant","content":None,"tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"file_path\":\"a.txt\"}"}}]},
      {"role":"tool","tool_call_id":"c1","content":big}]
req=urllib.request.Request(BASE+"/v1/chat/completions",json.dumps({"model":"llama3.2:3b","messages":msgs,"max_tokens":5,"temperature":0}).encode(),{"Content-Type":"application/json","Authorization":"Bearer dummy"})
t=time.time()
try:
    with urllib.request.urlopen(req,timeout=240) as r:
        d=json.load(r); print("HTTP",r.status,"in %.1fs"%(time.time()-t),"usage",d.get("usage"))
except urllib.error.HTTPError as e:
    print("HTTP",e.code,e.read()[:200])
print("ps",json.load(urllib.request.urlopen(BASE+"/api/ps",timeout=30)).get("models",[{}])[0].get("context_length"))
urllib.request.urlopen(urllib.request.Request(BASE+"/api/generate",json.dumps({"model":"llama3.2:3b","keep_alive":0}).encode(),{"Content-Type":"application/json"}),timeout=60).read()
time.sleep(1)
print("after unload",json.load(urllib.request.urlopen(BASE+"/api/ps",timeout=30)))
