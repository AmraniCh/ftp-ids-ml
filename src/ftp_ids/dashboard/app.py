from flask import Flask, render_template, request, redirect, url_for
from ftp_ids.core.storage import Storage

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("dashboard.html")

def serve(host: str = "127.0.0.1", port: int = 8080):
    print(f"Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)