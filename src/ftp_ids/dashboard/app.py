from flask import Flask, render_template, request
from ftp_ids.dashboard.stats import compute_stats, alerts_per_hour
from ftp_ids.dashboard.alerts_service import list_alerts, get_alert

app = Flask(__name__)

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

def serve(host: str = "127.0.0.1", port: int = 8080):
    print(f"Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)