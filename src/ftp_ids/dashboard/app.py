from flask import Flask, render_template, request, redirect, url_for
from ftp_ids.dashboard.stats import compute_stats, alerts_per_hour
from ftp_ids.dashboard.alerts_service import list_alerts, get_alert, mark_alert_normal
from datetime import datetime

app = Flask(__name__)

@app.template_filter("ts")
def ts(value):
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(value)

@app.route("/")
def index():
    return render_template(
        "dashboard.html", 
        stats=compute_stats(),
        hourly=alerts_per_hour(),
    )

@app.route("/alerts")
def alerts():
    page = int(request.args.get("page", 1))
    data = list_alerts(page=page)
    return render_template("alerts.html", **data)

@app.route("/alerts/<src_ip>/<path:start_time>")
def alert_detail(src_ip, start_time):
    alert = get_alert(src_ip, start_time)
    if not alert:
        return "Alert not found", 404
    return render_template("alert_detail.html", alert=alert)

@app.route("/alerts/mark-normal", methods=["POST"])
def mark_normal():
    src_ip = request.form["src_ip"]
    start_time = request.form["start_time"]
    mark_alert_normal(src_ip, start_time)
    return redirect(url_for("alerts"))

def serve(host: str = "127.0.0.1", port: int = 8080):
    print(f"Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)