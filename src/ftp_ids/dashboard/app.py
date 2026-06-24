from flask import Flask, render_template, request, redirect, url_for, flash
from ftp_ids.dashboard.stats import compute_stats, alerts_per_hour, is_watch_running
from ftp_ids.dashboard.alerts_service import list_alerts, get_alert, mark_alert_normal, unmark_alert_normal
from datetime import datetime
from ftp_ids.core.storage import Storage
from flask import jsonify
from ftp_ids.dashboard.retrain_service import retrain_model

app = Flask(__name__)
app.secret_key = "dev-secret-key" # for flash messages

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

@app.route("/live")
def live():
    return render_template("live.html")

@app.route("/api/alerts/recent")
def recent_alerts():
    since = request.args.get("since")
    
    storage = Storage()
    df = storage.load_alerts()
    if df.empty:
        return jsonify([])
    
    if since:
        # replace T with space on both sides and compare as strings
        normalized = df["start_time"].astype(str).str.replace("T", " ")
        df = df[normalized >= since.replace("T", " ")]
    
    df = df.sort_values("start_time", ascending=False).head(50)
    return jsonify(df.fillna("").to_dict(orient="records"))

@app.route("/alerts/unmark", methods=["POST"])
def unmark():
    unmark_alert_normal(request.form["src_ip"], request.form["start_time"])
    return redirect(url_for("alerts"))


@app.route("/retrain", methods=["POST"])
def retrain():
    result = retrain_model()
    if result["status"] == "ok":
        flash("Apply done · " + result["output"].strip().split('\n')[-1], "success")
    else:
        flash("Error · " + result["message"], "error")
    return redirect(url_for("alerts"))

@app.context_processor
def inject_globals():
    return {"is_watching": is_watch_running()}

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

def serve(host: str = "127.0.0.1", port: int = 8080):
    print(f"Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)