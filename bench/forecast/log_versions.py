import json,sys,pathlib,collections
R=pathlib.Path(sys.argv[1])
MODELS=["gpt-4o-2024-05-13","gpt-4o-mini-2024-07-18","gemini-2.0-flash-001","meta-llama_Llama-3.3-70B-Instruct","claude-3-7-sonnet-20250219","claude-3-5-sonnet-20241022"]
for m in MODELS:
    c=collections.Counter(); k=None; turns=[]; tcalls=[]; fin=collections.Counter()
    for f in (R/m).glob("*/user_task_*/important_instructions/injection_task_*.json"):
        d=json.load(open(f,encoding="utf-8"))
        c[(d.get("benchmark_version"),d.get("agentdojo_package_version"))]+=1
        msgs=d["messages"]
        turns.append(sum(1 for x in msgs if x["role"]=="assistant"))
        tcalls.append(sum(1 for x in msgs if x["role"]=="tool"))
    nt=[]
    for f in (R/m).glob("*/user_task_*/none/none.json"):
        d=json.load(open(f,encoding="utf-8"))
        nt.append(sum(1 for x in d["messages"] if x["role"]=="assistant"))
    import statistics as st
    print(m,dict(c),"attack turns mean %.2f median %s p90 %s max %s | benign turns mean %.2f max %s"%(st.mean(turns),st.median(turns),sorted(turns)[int(.9*len(turns))],max(turns),st.mean(nt),max(nt)))
