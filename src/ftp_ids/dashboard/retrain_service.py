import subprocess

def retrain_model():
    result = subprocess.run(
        ["ftp-ids", "retrain"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return {"status": "ok", "output": result.stdout}
    else:
        return {"status": "error", "message": result.stderr or result.stdout}
        