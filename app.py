
import json
from pathlib import Path

from flask import Flask, render_template

from scanner import scan_config


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent


@app.route("/")
def dashboard():
    config_path = BASE_DIR / "sample_config.json"

    with config_path.open(encoding="utf-8") as file:
        config = json.load(file)

    findings = scan_config(config)

    total_findings = len(findings)

    high_findings = sum(
        1 for finding in findings
        if finding["severity"] == "HIGH"
    )

    return render_template(
        "index.html",
        findings=findings,
        total_findings=total_findings,
        high_findings=high_findings
    )


if __name__ == "__main__":
    app.run(debug=True)
