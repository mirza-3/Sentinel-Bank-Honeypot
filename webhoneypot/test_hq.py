#!/usr/bin/env python
"""Minimal test to check if /hq route works"""

from flask import Flask, render_template_string

app2 = Flask(__name__)

HQ_TEST_HTML = r"""<!DOCTYPE html>
<html>
<head><title>HQ Test</title></head>
<body>
<h1>HQ Dashboard Test</h1>
<p>If you see this, the /hq route works!</p>
</body>
</html>
"""

@app2.route("/hq")
def hq_test():
    return render_template_string(HQ_TEST_HTML)

@app2.route("/")
def index():
    return "<h1>Index</h1><p><a href='/hq'>Go to /hq</a></p>"

if __name__ == "__main__":
    print("Starting test app on port 5001...")
    app2.run(host="127.0.0.1", port=5001, debug=False)
