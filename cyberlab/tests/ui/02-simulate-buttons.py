import json, os

SHOTS = r"C:\Users\codew\AppData\Local\Temp\claude\d--cyberlab\1be4e2c1-dbc5-427c-b615-7ec539719683\scratchpad\shots"
BASE = "http://localhost"

def rec(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" - " + str(detail)) if detail else ""))

def api_count(path):
    return int(js("fetch('%s').then(r=>r.json()).then(d=>d.length)" % path))

new_tab(BASE + "/security-lab/attacks"); wait_for_load(); wait(3)
before = api_count("/api/security/incidents")
labels = json.loads(js("JSON.stringify([...document.querySelectorAll('button')].map(b=>b.innerText.trim()).filter(t=>/^simulate|^re-run/i.test(t)))"))
rec("9 simulate buttons present", len(labels) == 9, len(labels))

for i in [7, 8]:
    label = json.loads(js("JSON.stringify([...document.querySelectorAll('button')].map(b=>b.innerText.trim()).filter(t=>/^simulate|^re-run/i.test(t)))"))[i]
    js("(() => { const bs=[...document.querySelectorAll('button')].filter(b=>/^simulate|^re-run/i.test(b.innerText.trim())); bs[%d].click(); return 1 })()" % i)
    wait(1)
    # wait until no button says Running
    for _ in range(40):
        running = js("[...document.querySelectorAll('button')].some(b=>/running/i.test(b.innerText))")
        if not running:
            break
        wait(1)
    wait(1)
    out = js("document.body.innerText")
    got_steps = "Step" in out or "Login" in out
    inc_created = bool(js("/incident/i.test(document.body.innerText)"))
    rec("simulate [%s]" % label, got_steps and inc_created and not running, "steps_shown=%s" % got_steps)

capture_screenshot(os.path.join(SHOTS, "attacks_after_sims.png"), full=False)
after = api_count("/api/security/incidents")
rec("incidents increased after sims", after > before, "before=%d after=%d" % (before, after))
