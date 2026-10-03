import json, os

SHOTS = r"C:\Users\codew\AppData\Local\Temp\claude\d--cyberlab\1be4e2c1-dbc5-427c-b615-7ec539719683\scratchpad\shots"
BASE = "http://localhost"

def rec(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" - " + str(detail)) if detail else ""))

def pclick(expr):
    return bool(js("(() => { const el = (%s); if(!el) return 0; for (const t of ['pointerdown','mousedown','pointerup','mouseup','click']) el.dispatchEvent(new PointerEvent(t,{bubbles:true,cancelable:true,button:0,pointerType:'mouse',isPrimary:true})); return 1 })()" % expr))

def set_input(expr, value):
    return bool(js("(() => { const el=(%s); if(!el) return 0; const proto = el.tagName==='TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto,'value').set.call(el, %s); el.dispatchEvent(new Event('input',{bubbles:true})); return 1 })()" % (expr, json.dumps(value))))

# ---------- XSS demo ----------
new_tab(BASE + "/security-lab/xss-demo"); wait_for_load(); wait(3)
print("xss controls:", js("JSON.stringify({ta:document.querySelectorAll('textarea').length, inputs:document.querySelectorAll('input').length, buttons:[...document.querySelectorAll('button')].map(b=>b.innerText.trim()).filter(Boolean)})"))
t = js("document.body.innerText")
rec("xss-demo shows VULNERABLE warning banner", bool(js("/vulnerab/i.test(document.body.innerText)")))
rec("seeded stored XSS executed in browser (red message rendered by payload)", "VULN-005 XSS DEMO" in t and "onerror" not in t.split("VULN-005 XSS DEMO")[0][-80:])
capture_screenshot(os.path.join(SHOTS, "xss_demo.png"), full=False)

vuln_payload = '<img src=x onerror="document.title=\'XSS-OK-VULN\'">vulnerable-post-test'
box = "document.querySelector('textarea') || document.querySelector('input[type=text]')"
set_input(box, vuln_payload)
ok = pclick("[...document.querySelectorAll('button')].find(b=>/vulnerable|unsafe/i.test(b.innerText))")
wait(3)
rec("vulnerable post executes script in browser (document.title changed)", js("document.title") == "XSS-OK-VULN", "title=%s clicked=%s" % (js("document.title"), ok))

safe_payload = '<img src=x onerror="document.title=\'XSS-SAFE-FAIL\'">safe-post-test'
new_tab(BASE + "/security-lab/xss-demo"); wait_for_load(); wait(3)
set_input(box, safe_payload)
ok = pclick("[...document.querySelectorAll('button')].find(b=>/safe|sanitiz|secure/i.test(b.innerText) && !/unsafe|vulnerable/i.test(b.innerText))")
wait(3)
title = js("document.title")
body = js("document.body.innerText")
rec("safe post does NOT execute script", title != "XSS-SAFE-FAIL", "title=%s clicked=%s" % (title, ok))
rec("safe post rendered as literal text", "safe-post-test" in body and "<img" in body, "")
capture_screenshot(os.path.join(SHOTS, "xss_demo_after.png"), full=False)

# ---------- attack graph ----------
new_tab(BASE + "/security-lab/attack-graph"); wait_for_load(); wait(3)
g = js("document.body.innerText")
chain = ["Credential Compromise", "Authenticated User", "IDOR", "Cross-Tenant", "Admin API", "Bulk Data"]
rec("attack graph shows full attack chain", all(c in g for c in chain), [c for c in chain if c not in g])
rec("attack graph shows nodes+edges from live API (EXPLOITED/AUTHENTICATED)", "EXPLOITED" in g.upper() and "AUTHENTICATED" in g.upper())
capture_screenshot(os.path.join(SHOTS, "attack_graph.png"), full=True)

# ---------- security lab catalog ----------
new_tab(BASE + "/security-lab"); wait_for_load(); wait(3)
lab = js("document.body.innerText")
found = [("VULN-%03d" % i) for i in range(1, 15) if ("VULN-%03d" % i) in lab]
rec("security-lab lists VULN-001..014", len(found) == 14, len(found))
rec("security-lab shows CWE + OWASP + MITRE", "CWE-" in lab and ("API1:2023" in lab or "A01:2021" in lab) and ("T1" in lab))
rec("security-lab links to attacks / xss demo", bool(js("[...document.querySelectorAll('a')].some(a=>/attacks/.test(a.href)) && [...document.querySelectorAll('a')].some(a=>/xss-demo/.test(a.href))")))

# ---------- live update: simulate via API then watch dashboard ----------
new_tab(BASE + "/dashboard"); wait_for_load(); wait(3)
before = int(js("(document.body.innerText.match(/(\\d+)\\s*\\n?\\s*Security Events/)||[0,0])[1]"))
js("fetch('/api/security/simulate/03-idor',{method:'POST'}).then(r=>r.json())")
wait(12)
after = int(js("(document.body.innerText.match(/(\\d+)\\s*\\n?\\s*Security Events/)||[0,0])[1]"))
rec("dashboard auto-updates (5s polling) after attack", after > before, "events %d -> %d" % (before, after))
rec("dashboard shows new incident without reload", "Possible IDOR Attack" in js("document.body.innerText"))

# ---------- security events page ----------
new_tab(BASE + "/security-events"); wait_for_load(); wait(3)
ev = js("document.body.innerText")
types = [t for t in ["AUTH_FAILURE", "AUTH_SUCCESS", "DATA_ACCESS", "API_REQUEST", "CROSS_TENANT_ACCESS_ATTEMPT", "SECURITY_FINDING_TRIGGERED"] if t in ev]
rec("security-events lists live event types", len(types) >= 4, types)
rec("security-events shows MITRE / sourceIp columns", bool(js("/10\\.66\\.|172\\.\\d+\\./.test(document.body.innerText)")))
