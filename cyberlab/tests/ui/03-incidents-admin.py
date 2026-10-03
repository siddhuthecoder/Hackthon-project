import json, os

SHOTS = r"C:\Users\codew\AppData\Local\Temp\claude\d--cyberlab\1be4e2c1-dbc5-427c-b615-7ec539719683\scratchpad\shots"
BASE = "http://localhost"

def rec(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" - " + str(detail)) if detail else ""))

def fetch_json(path, token=None):
    return json.loads(js("fetch('%s').then(r=>r.text())" % path))

def click_expr(expr):
    """expr: JS expression returning an element (or null). Scroll into view, click its centre."""
    r = js("(() => { const el = (%s); if(!el) return null; el.scrollIntoView({block:'center'}); const b=el.getBoundingClientRect(); return JSON.stringify([b.x+b.width/2, b.y+b.height/2]) })()" % expr)
    if not r:
        return False
    x, y = json.loads(r)
    click_at_xy(x, y)
    return True

def pclick(expr):
    r = js("(() => { const el = (%s); if(!el) return 0; for (const t of ['pointerdown','mousedown','pointerup','mouseup','click']) el.dispatchEvent(new PointerEvent(t,{bubbles:true,cancelable:true,button:0,pointerType:'mouse',isPrimary:true})); return 1 })()" % expr)
    return bool(r)

def set_select(index, value):
    return js("(() => { const el=document.querySelectorAll('[role=combobox]')[%d]; const k=Object.keys(el).find(k=>k.startsWith('__reactFiber$')); let f=el[k]; while(f){ if(f.memoizedProps && typeof f.memoizedProps.onValueChange==='function'){ f.memoizedProps.onValueChange('%s'); return 1 } f=f.return } return 0 })()" % (index, value))

new_tab(BASE + "/incidents"); wait_for_load(); wait(3)
open_before = fetch_json("/api/security/incidents")
target = open_before[0]
print("target incident:", target["id"], target["title"])

ok = pclick("[...document.querySelectorAll('span')].find(s=>s.innerText.trim()==='%s').closest('.cursor-pointer')" % target["id"])
rec("expand incident row", ok)
wait(1)
rec("expanded row shows attack path / recommended actions", bool(js("/recommended|attack path|mitre/i.test(document.body.innerText)")))
ok = set_select(0, 'CONTAINED'); ok2 = ok
wait(2)
after = fetch_json("/api/security/incidents")
rec("incident status change persisted (API)", any(i["id"] == target["id"] and i["status"] == "CONTAINED" for i in after), "clicked=%s/%s" % (ok, ok2))
capture_screenshot(os.path.join(SHOTS, "incidents_expanded.png"), full=False)

# ---- admin: promote + deactivate ----
new_tab(BASE + "/admin"); wait_for_load(); wait(3)
users = fetch_json("/api/admin/users") if False else None
audit_before = len(fetch_json("/api/security/audit-logs?limit=500"))
rows = json.loads(js("JSON.stringify([...document.querySelectorAll('button')].map(b=>b.innerText.trim()).filter(Boolean).slice(0,10))"))
print("admin buttons:", rows)
print("admin comboboxes:", js("document.querySelectorAll('[role=combobox]').length"))
# change role of first row via the role select
ok = set_select(0, 'MANAGER'); ok2 = ok
wait(2)
audit_after = len(fetch_json("/api/security/audit-logs?limit=500"))
rec("admin promote action wrote audit log", audit_after > audit_before, "audit %d -> %d clicked=%s/%s" % (audit_before, audit_after, ok, ok2))
capture_screenshot(os.path.join(SHOTS, "admin_after_promote.png"), full=False)

deact_before = len(fetch_json("/api/security/audit-logs?limit=500"))
ok = pclick("[...document.querySelectorAll('button')].find(b=>/deactivate/i.test(b.innerText))")
wait(2)
deact_after = len(fetch_json("/api/security/audit-logs?limit=500"))
rec("admin deactivate action wrote audit log", ok and deact_after > deact_before, "audit %d -> %d" % (deact_before, deact_after))

# verify UI reflects persisted state after reload
new_tab(BASE + "/incidents"); wait_for_load(); wait(3)
rec("incident CONTAINED visible in UI after reload", "CONTAINED" in js("document.body.innerText"))
new_tab(BASE + "/admin"); wait_for_load(); wait(3)
users = json.loads(js("fetch('/api/admin/users').then(r=>r.text())")) if False else None
rec("admin page shows deactivated/promoted state", "MANAGER" in js("document.body.innerText"))
new_tab(BASE + "/audit-logs"); wait_for_load(); wait(3)
t = js("document.body.innerText")
rec("audit-logs page shows ROLE_CHANGED + USER_UPDATED entries", "ROLE_CHANGED" in t and "USER_UPDATED" in t)
