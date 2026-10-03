# UI tests (browser-harness)

Run with Chrome remote debugging enabled and the lab up:

    browser-harness < tests/ui/01-pages.py
    browser-harness < tests/ui/02-simulate-buttons.py
    browser-harness < tests/ui/03-incidents-admin.py
    browser-harness < tests/ui/04-xss-graph-live.py

Radix Select popups ignore synthetic CDP clicks, so the tests call the Select onValueChange handler through the React fiber. Each script prints PASS/FAIL lines. Reseed afterwards: ./scripts/seed.sh
