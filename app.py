import os
import requests

from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


app = Flask(__name__)

AES_KEY = bytes([
    89, 103, 38, 116, 99, 37, 68, 69,
    117, 104, 54, 37, 90, 99, 94, 56
])

AES_IV = bytes([
    54, 111, 121, 90, 68, 114, 50, 50,
    69, 51, 121, 99, 104, 106, 77, 37
])

API_URL = "https://loginbp.ppmainecoonghj.com/MajorModifyNickname"

HEADERS = {
    "User-Agent": (
        "UnityPlayer/2022.3.47f1 "
        "(UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
    ),
    "X-GA": "v1 1",
    "ReleaseVersion": "OB55",
    "Content-Type": "application/octet-stream",
    "X-Unity-Version": "2022.3.47f1"
}


def encode_varint(number):
    result = bytearray()

    while number > 127:
        result.append((number & 127) | 128)
        number >>= 7

    result.append(number)
    return bytes(result)


def build_payload(nickname):
    name = nickname.encode("utf-8")

    return (
        encode_varint(10)
        + encode_varint(len(name))
        + name
        + encode_varint(16)
        + encode_varint(1)
    )


def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def change_nickname(jwt, nickname):
    headers = {
        **HEADERS,
        "Authorization": f"Bearer {jwt}"
    }

    response = requests.post(
        API_URL,
        headers=headers,
        data=encrypt_data(build_payload(nickname)),
        timeout=20
    )

    try:
        result = response.json()
    except ValueError:
        result = response.text

    return response.status_code, result


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "Rishu Nickname API",
        "status": "online",
        "method": "GET",
        "endpoint": "/rishu?Name=<nickname>&jwt=<token>"
    })


@app.route("/rishu", methods=["GET"])
def rishu():
    nickname = request.args.get("Name", "").strip()
    jwt = request.args.get("jwt", "").strip()

    if not nickname or not jwt:
        return jsonify({
            "success": False,
            "error": "Name and jwt parameters are required"
        }), 400

    if len(nickname) > 100:
        return jsonify({
            "success": False,
            "error": "Nickname is too long"
        }), 400

    try:
        status, result = change_nickname(jwt, nickname)

        return jsonify({
            "success": status == 200,
            "http_status": status,
            "nickname": nickname,
            "response": result
        }), 200 if status == 200 else 502

    except requests.Timeout:
        return jsonify({
            "success": False,
            "error": "Request timed out"
        }), 504

    except requests.RequestException:
        return jsonify({
            "success": False,
            "error": "Upstream service unavailable"
        }), 502


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": "GET requests only"
    }), 405


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )