from flask import Flask, render_template, request, send_from_directory
import os
import subprocess

from config.settings import DATA_DIR, REPORT_DIR

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, REPORT_DIR)
DATA_DIR_PATH = os.path.join(BASE_DIR, DATA_DIR)

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(DATA_DIR_PATH, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    target = ""
    report_file = None
    json_file = None
    success = False

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if target:
            try:
                process = subprocess.run(
                    ["python", "main.py", "-t", target],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=BASE_DIR,
                )

                result = process.stdout

                if process.stderr:
                    result += "\n\n--- Logs ---\n"
                    result += process.stderr

                expected_report = f"{target}_report.md"
                expected_json = f"{target}_osint.json"

                report_path = os.path.join(REPORTS_DIR, expected_report)
                json_path = os.path.join(DATA_DIR_PATH, expected_json)

                if os.path.isfile(report_path):
                    report_file = expected_report

                if os.path.isfile(json_path):
                    json_file = expected_json

                success = bool(report_file or json_file)

            except subprocess.TimeoutExpired:
                result = "Scan timed out after 10 minutes."
            except Exception as exc:
                result = f"Error running scan: {exc}"

    return render_template(
        "index.html",
        result=result,
        target=target,
        report_file=report_file,
        json_file=json_file,
        success=success,
    )


@app.route("/report/<path:filename>")
def view_report(filename):
    safe_filename = os.path.basename(filename)
    report_path = os.path.join(REPORTS_DIR, safe_filename)

    if not os.path.isfile(report_path):
        return "Report not found.", 404

    with open(report_path, "r", encoding="utf-8") as file:
        content = file.read()

    return render_template(
        "report.html",
        title="OSINT Markdown Report",
        content=content,
    )


@app.route("/json/<path:filename>")
def view_json(filename):
    safe_filename = os.path.basename(filename)
    json_path = os.path.join(DATA_DIR_PATH, safe_filename)

    if not os.path.isfile(json_path):
        return "JSON report not found.", 404

    return send_from_directory(
        DATA_DIR_PATH,
        safe_filename,
        mimetype="application/json",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
