#!/usr/bin/env python
"""Minimal test to debug /hq route issue"""

from flask import Flask, render_template_string

app_debug = Flask(__name__)

TEST_HTML = r"""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><h1>Test Page</h1></body>
</html>"""

@app_debug.route("/hq")
def hq_test():
    return render_template_string(TEST_HTML)

@app_debug.route("/test")
def test():
    return "<h1>Test</h1>"

@app_debug.route("/")
def index():
    return "<h1>Index</h1><p><a href='/hq'>HQ</a> <a href='/test'>Test</a></p>"

if __name__ == "__main__":
    print("Testing routes...")
    with app_debug.test_client() as client:
        r1 = client.get('/')
        r2 = client.get('/test')
        r3 = client.get('/hq')
        
        print(f"/ -> {r1.status_code}")
        print(f"/test -> {r2.status_code}")
        print(f"/hq -> {r3.status_code}")
        
    print("\nStarting server on 127.0.0.1:5555...")
    print("Visit in browser: http://127.0.0.1:5555/hq")
    app_debug.run(host='127.0.0.1', port=5555, debug=False)
