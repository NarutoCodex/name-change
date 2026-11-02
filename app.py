import asyncio
import binascii
import json
import threading
import time
import urllib.request

import aiohttp
import ssl
from flask import Flask, request, jsonify

from JwtGen import (
    GeNeRaTeAccEss,
    Access_Info,
    EncryptMajorLoginManual,
    MajorLogin,
    DeCode_PackEt,
    CrEaTe_ProTo,
    encrypted_proto,
    Ob_VerSion,
    lOgIn_UrL,
)

app = Flask(__name__)

BASE_URL = "https://your-app-name.onrender.com"
KEEP_ALIVE_INTERVAL = 180
KEEP_ALIVE_START_DELAY = 30


def normalize_server(s):
    if not s:
        return None
    s = str(s).strip().rstrip("/")
    if not s:
        return None
    if not s.startswith("http"):
        s = "https://" + s
    return s


async def get_credentials(token_type, token):
    t = token_type.strip().lower()

    if t in ("uid-pass", "uidpass", "uid_pass"):
        if ":" not in token:
            raise ValueError("token must be 'uid:password'")
        uid, password = token.split(":", 1)
        res = await GeNeRaTeAccEss(uid, password)
        if len(res) == 3:
            return res
        return res[0], res[1], None

    if t in ("access", "token", "access_token"):
        open_id, platform = await Access_Info(token)
        return open_id, token, platform

    raise ValueError("unknown token-type: " + token_type)


async def do_modify(nickname, open_id, access_token, platform):
    login_req = await EncryptMajorLoginManual(open_id, access_token, platform)
    login_resp = await MajorLogin(login_req)
    if not login_resp:
        return None, "MajorLogin failed"

    try:
        decoded = await DeCode_PackEt(binascii.hexlify(login_resp).decode())
        data = json.loads(decoded)
    except Exception as e:
        return None, "decode error: " + str(e)

    if "13" in data:
        return None, "account banned"

    jwt = data["8"]["data"]

    login_server = (
        normalize_server(lOgIn_UrL)
        or normalize_server(data.get("9", {}).get("data"))
        or normalize_server(data["10"]["data"])
    )
    if not login_server:
        return None, "no login server url"

    modify_url = login_server + "/MajorModifyNickname"

    fields = {1: nickname, 2: 1}
    proto = await CrEaTe_ProTo(fields)
    payload = await encrypted_proto(proto)

    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())),
        "Authorization": "Bearer " + jwt,
        "X-Ga": "v1 1",
        "ReleaseVersion": Ob_VerSion,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as session:
        async with session.post(modify_url, data=payload, headers=headers, ssl=ctx) as r:
            body = await r.read()
            status = r.status

    if len(body) > 64:
        body = body[64:]

    return (status, body, modify_url), None


@app.route("/health", methods=["GET"])
def health():
    return jsonify(ok=True, time=int(time.time()))


@app.route("/MajorModifyNickname", methods=["GET"])
def modify_nickname():
    nickname = request.headers.get("logindata") or request.args.get("name")
    token_type = request.headers.get("token-type") or request.args.get("token_type")
    token = request.headers.get("token") or request.args.get("token")

    if not (nickname and token_type and token):
        return jsonify(error="logindata, token-type, token required"), 400

    async def run():
        open_id, access_token, platform = await get_credentials(token_type, token)
        if not open_id or not access_token:
            return None, "credential failure"
        return await do_modify(nickname, open_id, access_token, platform)

    try:
        result, err = asyncio.run(run())
    except Exception as e:
        return jsonify(error=str(e)), 500

    if err:
        return jsonify(error=err), 500

    status, body, url = result

    decoded = None
    new_name = None
    try:
        dec_json = asyncio.run(DeCode_PackEt(binascii.hexlify(body).decode()))
        decoded = json.loads(dec_json) if dec_json else None
        if decoded and "1" in decoded:
            new_name = decoded["1"].get("data")
    except Exception:
        pass

    return jsonify(
        status=status,
        url=url,
        new_name=new_name,
        hex=binascii.hexlify(body).decode(),
        decoded=decoded,
    )


def _keep_alive_loop():
    target = BASE_URL.rstrip("/") + "/health"
    time.sleep(KEEP_ALIVE_START_DELAY)
    while True:
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "keep-alive/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                r.read(1)
        except Exception:
            pass
        time.sleep(KEEP_ALIVE_INTERVAL)


def start_keep_alive():
    threading.Thread(target=_keep_alive_loop, name="keep-alive", daemon=True).start()


start_keep_alive()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)