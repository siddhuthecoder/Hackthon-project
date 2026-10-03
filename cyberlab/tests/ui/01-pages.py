import json, os, time

SHOTS = r"C:\Users\codew\AppData\Local\Temp\claude\d--cyberlab\1be4e2c1-dbc5-427c-b615-7ec539719683\scratchpad\shots"
os.makedirs(SHOTS, exist_ok=True)
BASE = "http://localhost"
results = []

def rec(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ((" - " + str(detail)) if detail else ""))

def body():
    return js("document.body.innerText") or ""

def visit(path, settle=2.5):
    goto_url(BASE + path)
    wait_for_load()
    wait(settle)

# capture console errors via injected hook (per page)
HOOK = "window.__errs=[];window.addEventListener('error',e=>window.__errs.push(String(e.message)));const oe=console.error;console.error=function(){window.__errs.push([].slice.call(arguments).join(' '));oe.apply(console,arguments)};1"

pages = ["/dashboard","/users","/tenants","/products","/orders","/admin","/security-events","/audit-logs","/incidents","/security-lab","/security-lab/attacks","/security-lab/attack-graph","/security-lab/xss-demo"]
for p in pages:
    visit(p)
    txt = body()
    errtxt = bool(js("/failed to load|application error|something went wrong|unhandled runtime/i.test(document.body.innerText)"))
    capture_screenshot(os.path.join(SHOTS, p.strip("/").replace("/", "_") + ".png"), full=True)
    rec("page " + p, len(txt) > 200 and not errtxt, "chars=%d" % len(txt))

