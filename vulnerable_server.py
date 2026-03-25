#!/usr/bin/env python3
"""Vulnerable TensorRT Model Server for Testing"""

import os
import subprocess
import tempfile
import base64
import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)

VULNERABLE_STORAGE = {
    "1": {"user": "alice", "model": "model_v1.engine", "data": "Alice's model data"},
    "2": {"user": "bob", "model": "model_v2.engine", "data": "Bob's private model"},
    "3": {"user": "charlie", "model": "model_v3.engine", "data": "Charlie's confidential data"},
    "999": {"user": "admin", "model": "admin.engine", "data": "ADMIN CREDENTIALS - SECRET DATA"},
}


@app.route("/api/model/<id>/load", methods=["POST"])
def model_load(id):
    """Vulnerable: IDOR - can access any user's model"""
    user_data = VULNERABLE_STORAGE.get(id, {"user": "unknown", "data": "Not found"})
    return jsonify(
        {"status": "loaded", "model_id": id, "user": user_data["user"], "data": user_data["data"]}
    )


@app.route("/api/model/<id>/validate", methods=["POST"])
def model_validate(id):
    """Vulnerable: Path traversal in file parameter"""
    file_param = request.args.get("file", "")

    if file_param.startswith("../"):
        try:
            with open(file_param, "r") as f:
                content = f.read()[:500]
            return jsonify({"status": "valid", "file": file_param, "content": content})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"status": "valid", "file": file_param})


@app.route("/api/model/<id>/convert", methods=["POST"])
def model_convert(id):
    """Vulnerable: SSRF and arbitrary file read"""
    input_file = request.args.get("input_file", "")

    if "http" in input_file:
        import urllib.request

        try:
            with urllib.request.urlopen(input_file, timeout=5) as resp:
                data = resp.read()
            return jsonify({"status": "converted", "size": len(data)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"status": "converted", "file": input_file})


@app.route("/api/model/<id>/cmd", methods=["POST"])
def model_cmd(id):
    """VULNERABLE: Command Injection"""
    cmd = request.args.get("cmd", "")

    try:
        result = subprocess.check_output(cmd, shell=True, timeout=5)
        return jsonify({"status": "success", "output": result.decode("utf-8", errors="ignore")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/model/<id>/parse", methods=["POST"])
def model_parse(id):
    """Vulnerable: Unsafe deserialization"""
    trt_data = request.args.get("trt_data", "")

    try:
        decoded = base64.b64decode(trt_data)
        if decoded.startswith(b"pickle"):
            obj = pickle.loads(decoded)
            return jsonify({"status": "parsed", "result": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "parsed", "size": len(trt_data)})


@app.route("/api/inference/<id>/predict", methods=["POST"])
def inference_predict(id):
    """IDOR: Can predict with other users' models"""
    user_data = VULNERABLE_STORAGE.get(id, {})
    return jsonify(
        {
            "prediction": "SENTITIVE_RESULT",
            "model_owner": user_data.get("user", "unknown"),
            "model_data": user_data.get("data", ""),
        }
    )


@app.route("/api/optimizer/tensorrt/<id>", methods=["POST"])
def tensorrt_optimizer(id):
    """Path traversal in engine path"""
    engine_path = request.args.get("engine_path", "")

    if ".." in engine_path:
        try:
            with open(engine_path, "rb") as f:
                return jsonify({"status": "optimized", "file": engine_path, "size": len(f.read())})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"status": "optimized", "engine": engine_path})


@app.route("/api/model/<id>/upload", methods=["POST"])
def model_upload(id):
    """RCE via file upload - stores malicious engine"""
    file = request.files.get("file")
    if file:
        filepath = f"/tmp/uploaded_{id}.engine"
        file.save(filepath)
        return jsonify({"status": "uploaded", "path": filepath})
    return jsonify({"error": "no file"}), 400


@app.route("/api/model/<id>/benchmark", methods=["POST"])
def model_benchmark(id):
    """DoS via large iterations"""
    iterations = int(request.args.get("iterations", "100"))
    if iterations > 10000:
        return jsonify({"error": "Too many iterations"}), 400
    return jsonify({"status": "benchmarking", "iterations": iterations})


@app.route("/api/admin/models", methods=["GET"])
def admin_models():
    """IDOR: Admin endpoint accessible without proper auth"""
    return jsonify({"admin": True, "all_models": list(VULNERABLE_STORAGE.values())})


@app.route("/api/model/<id>/compare", methods=["POST"])
def model_compare(id):
    """LFI via compare endpoint"""
    model_a = request.args.get("model_a", "")
    model_b = request.args.get("model_b", "")

    results = []
    for model in [model_a, model_b]:
        if ".." in model:
            try:
                with open(model, "r") as f:
                    results.append(f.read()[:200])
            except:
                pass

    return jsonify({"compare": results})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "vulnerable": True})


if __name__ == "__main__":
    print("=" * 60)
    print("VULNERABLE TENSORRT SERVER")
    print("DO NOT RUN IN PRODUCTION")
    print("=" * 60)
    print("\nEndpoints:")
    print("  /api/model/<id>/load     - IDOR vulnerable")
    print("  /api/model/<id>/validate - Path traversal")
    print("  /api/model/<id>/cmd      - COMMAND INJECTION")
    print("  /api/model/<id>/parse    - Unsafe deserialization")
    print("  /api/inference/<id>/predict - IDOR")
    print("  /api/model/<id>/upload   - RCE via upload")
    print("  /api/admin/models        - No auth required")
    print("\n" + "=" * 60)

    app.run(host="127.0.0.1", port=5000, debug=True)
