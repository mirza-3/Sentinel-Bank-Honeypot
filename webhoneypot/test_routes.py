#!/usr/bin/env python
"""Test script to verify Flask routes are registered correctly"""

from app import app

print("\n====== REGISTERED FLASK ROUTES ======\n")

for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
    methods = ','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
    print(f"{str(rule):<40} {methods}")

print(f"\n====== TOTAL ROUTES: {len(list(app.url_map.iter_rules()))} ======\n")

# Check specifically for /hq
hq_routes = [r for r in app.url_map.iter_rules() if '/hq' in str(r)]
print(f"Routes containing '/hq': {hq_routes}")
