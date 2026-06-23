from flask import Flask, render_template
from ftp_ids.dashboard.stats import compute_stats

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("dashboard.html", stats=compute_stats())

def serve(host: str = "127.0.0.1", port: int = 8080):
    print(f"Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)