"""
سيرفر كورساتك - مستقل تماماً، مالوش أي علاقة بأي منصة تانية
================================================================
الفكرة:
- الأدمن بيحط توكن الـ JWT بتاع كورساتك مرة واحدة في السيرفر (مش في المتصفح)
- الطالب يدخل PIN -> يرجع Session Token خاص بيه
- أي طلب بعد كده (مواد / مدرسين / شهور / محاضرات / فيديو) بيعدي من عندنا،
  إحنا اللي بنكلم كورساتك بالتوكن الحقيقي، والطالب مايشوفش التوكن ده خالص
"""

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, db
import requests
import time
import os
import json
import secrets
import base64
from urllib.parse import urljoin, urlparse

app = Flask(__name__)
CORS(app, resources={r"/*": {
    "origins": "*",
    "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization", "X-Admin-Password", "Range"],
    "expose_headers": ["Content-Length", "Content-Range", "Accept-Ranges"],
}})

# =========================================================
ADMIN_PASSWORD = "Coursatk#2026$Secure!Panel77"
DATABASE_URL = "https://english-73376-default-rtdb.firebaseio.com"
SERVICE_ACCOUNT_PATH = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")

COURSATK_BASE = "https://api.coursatk.online/api/v1"

# كل بيانات المنصة دي تحت مسار واحد منفصل خالص في قاعدة البيانات
NODE_STUDENTS = "coursatk_students"
NODE_CONFIG = "coursatk_config"
NODE_SESSIONS = "coursatk_sessions"
# =========================================================

firebase_env_creds = os.environ.get("FIREBASE_CREDENTIALS_JSON")
if firebase_env_creds:
    cred = credentials.Certificate(json.loads(firebase_env_creds))
else:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)

firebase_admin.initialize_app(cred, {"databaseURL": DATABASE_URL})


def check_admin(req):
    return req.headers.get("X-Admin-Password", "") == ADMIN_PASSWORD


def get_session_token(req):
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def get_valid_session(req):
    """يتحقق من الـ session token ويرجع بيانات الطالب لو صحيح، وإلا None"""
    token = get_session_token(req)
    if not token:
        return None
    session = db.reference(f"{NODE_SESSIONS}/{token}").get()
    if not session:
        return None
    student_id = session.get("studentId")
    student = db.reference(f"{NODE_STUDENTS}/{student_id}").get()
    if not student or not student.get("active", True):
        db.reference(f"{NODE_SESSIONS}/{token}").delete()
        return None
    return student


def get_coursatk_token():
    config = db.reference(NODE_CONFIG).get() or {}
    return config.get("token", "")


def coursatk_get(path):
    """بيبعت طلب لكورساتك بالتوكن المخزن عندنا، ويرجع (json_body, status_code)"""
    token = get_coursatk_token()
    if not token:
        return {"success": False, "message": "التوكن لسه متسجلش في اللوحة"}, 500

    headers = {
        "authorization": f"Bearer {token}",
        "accept": "*/*"
    }
    try:
        r = requests.get(f"{COURSATK_BASE}{path}", headers=headers, timeout=15)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return body, r.status_code
    except Exception as e:
        return {"success": False, "message": str(e)}, 502


# =========================================================
# الطالب: تسجيل الدخول
# =========================================================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pin", "")).strip()
    device_id = str(data.get("deviceId", "")).strip()

    if not pin or len(pin) != 6 or not pin.isdigit():
        return jsonify({"success": False, "message": "الكود لازم يكون 6 أرقام"}), 400
    if not device_id:
        return jsonify({"success": False, "message": "معرف الجهاز مفقود"}), 400

    students = db.reference(NODE_STUDENTS).get() or {}
    student_id, student = None, None
    for sid, info in students.items():
        if info.get("code") == pin:
            student_id, student = sid, info
            break

    if not student:
        return jsonify({"success": False, "message": "الكود غير صحيح"}), 404
    if not student.get("active", True):
        return jsonify({"success": False, "message": "هذا الحساب معطل"}), 403

    devices = student.get("devices", {}) or {}
    max_devices = student.get("maxDevices", 1)

    if device_id in devices:
        if isinstance(devices[device_id], dict) and devices[device_id].get("blocked"):
            return jsonify({"success": False, "message": "تم حظر هذا الجهاز"}), 403
    else:
        if len(devices) >= max_devices:
            return jsonify({
                "success": False,
                "message": f"تم الوصول للحد الأقصى لعدد الأجهزة ({max_devices})"
            }), 403
        devices[device_id] = {"firstSeen": int(time.time())}
        db.reference(f"{NODE_STUDENTS}/{student_id}/devices").set(devices)

    session_token = secrets.token_hex(32)
    db.reference(f"{NODE_SESSIONS}/{session_token}").set({
        "studentId": student_id,
        "deviceId": device_id,
        "createdAt": int(time.time())
    })

    return jsonify({
        "success": True,
        "sessionToken": session_token,
        "studentName": student.get("name", "")
    })


# =========================================================
# تشغيل الفيديو - Stream Weave Integration
# =========================================================
STREAM_WEAVE_BASE = "https://api.stream-weave.com"

def coursatk_post(path, data=None):
    """بيبعت POST request لكورساتك بالتوكن المخزن عندنا"""
    token = get_coursatk_token()
    if not token:
        return {"success": False, "message": "التوكن لسه متسجلش في اللوحة"}, 500

    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "accept": "*/*"
    }
    try:
        r = requests.post(f"{COURSATK_BASE}{path}", json=data or {}, headers=headers, timeout=15)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return body, r.status_code
    except Exception as e:
        return {"success": False, "message": str(e)}, 502


def stream_weave_request(method, path, data=None, token=None):
    """طلبات لـ stream weave بالتوكن المأخوذ من الرد بتاع كورساتك"""
    headers = {}
    if token:
        headers["authorization"] = f"Bearer {token}"
    headers["accept"] = "*/*"
    
    url = f"{STREAM_WEAVE_BASE}{path}"
    try:
        if method.upper() == "GET":
            r = requests.get(url, headers=headers, timeout=15)
        elif method.upper() == "POST":
            headers["content-type"] = "application/json"
            r = requests.post(url, json=data or {}, headers=headers, timeout=15)
        else:
            return {"success": False}, 400
        
        try:
            body = r.json()
        except Exception:
            body = r.text
        return body, r.status_code
    except Exception as e:
        return {"success": False, "message": str(e)}, 502


@app.route("/video/<int:video_id>/play", methods=["GET"])
def play_video(video_id):
    """تشغيل الفيديو - بيرجع stream URL و token و كل البيانات المطلوبة"""
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    # 1. طلب stream-weave/play من كورساتك
    play_body, play_status = coursatk_post(f"/video/{video_id}/stream-weave/play")
    
    if play_status != 200:
        return jsonify(play_body), play_status
    
    if not play_body.get("success"):
        return jsonify(play_body), 400
    
    stream_data = play_body.get("data", {})
    stream_token = stream_data.get("token")
    
    if not stream_token:
        return jsonify({"success": False, "message": "ما قدرش نحصل على الـ token"}), 500

    # ربما الكلايينت (الواجهة) هتبعت طلبات heartbeat لوحدها
    # بس احنا هنرجع كل البيانات اللي محتاجها
    
    return jsonify({
        "success": True,
        "data": stream_data,
        "streamToken": stream_token
    })



# =========================================================
# HLS INTERNAL PROXY
# =========================================================
# The browser receives only our own URLs. The upstream Stream-Weave
# access token stays server-side in this process.
#
# Flow:
#   /admin/video/<id>/play
#       -> Coursatk /stream-weave/play
#       -> server stores the upstream playback token
#       -> returns /admin/hls/<session>/master.m3u8
#
#   master.m3u8 / variant.m3u8 / key / .ts / .m4s / .woff2
#       -> fetched by this server and returned to the browser.
# =========================================================

HLS_SESSIONS = {}
HLS_SESSION_TTL = 8 * 60 * 60

# Only these upstream hosts are accepted by the internal proxy.
# This prevents the proxy from becoming an arbitrary SSRF endpoint.
ALLOWED_HLS_HOSTS = {
    "api.stream-weave.com",
    "api.streamweave.com",
    "stream-weave.com",
}

def _b64e(value):
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")

def _b64d(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii")).decode("utf-8")

def _cleanup_hls_sessions():
    now = time.time()
    expired = [
        sid for sid, item in HLS_SESSIONS.items()
        if now - item.get("createdAt", 0) > HLS_SESSION_TTL
    ]
    for sid in expired:
        HLS_SESSIONS.pop(sid, None)

def _create_hls_session(video_id, stream_data):
    _cleanup_hls_sessions()
    sid = secrets.token_urlsafe(32)

    HLS_SESSIONS[sid] = {
        "videoId": int(video_id),
        "token": stream_data.get("token", ""),
        "sessionId": stream_data.get("session_id", ""),
        "createdAt": time.time(),
        "expiresAt": time.time() + min(
            int(stream_data.get("expires_in") or HLS_SESSION_TTL),
            HLS_SESSION_TTL
        ),
    }
    return sid

def _get_hls_session(sid):
    item = HLS_SESSIONS.get(sid)
    if not item:
        return None
    if time.time() > item.get("expiresAt", 0):
        HLS_SESSIONS.pop(sid, None)
        return None
    return item

def _allowed_upstream(url):
    try:
        p = urlparse(url)
        return p.scheme in ("https", "http") and p.hostname in ALLOWED_HLS_HOSTS
    except Exception:
        return False

def _upstream_get(url, token, stream=True):
    headers = {
        "Accept": "*/*",
        "User-Agent": request.headers.get("User-Agent", "Coursatk-Internal-HLS-Proxy/1.0"),
    }

    # Forward Range because media players may request partial content.
    if request.headers.get("Range"):
        headers["Range"] = request.headers["Range"]

    # Stream-Weave API resources require the playback JWT.
    if urlparse(url).hostname in {"api.stream-weave.com", "api.streamweave.com"} and token:
        headers["Authorization"] = f"Bearer {token}"

    return requests.get(
        url,
        headers=headers,
        stream=stream,
        timeout=(10, 60),
        allow_redirects=True,
    )

def _rewrite_playlist(text, sid, current_url):
    """
    Rewrite every URI-bearing HLS line to an internal proxy URL.

    This covers:
      - master playlist variant URIs
      - media playlist .ts/.m4s/.woff2 URIs
      - EXT-X-KEY URI="..."
      - EXT-X-MAP URI="..."
      - EXT-X-PART URI="..."
      - EXT-X-PRELOAD-HINT URI="..."
      - EXT-X-MEDIA URI="..."
      - other URI="..." attributes
    """
    lines = text.splitlines()
    out = []

    for line in lines:
        stripped = line.strip()

        # URI="..." inside HLS tags.
        def repl_uri(match):
            raw = match.group(1)
            absolute = urljoin(current_url, raw)
            if not _allowed_upstream(absolute):
                return match.group(0)
            return 'URI="/admin/hls/{}/resource?u={}"'.format(
                sid, _b64e(absolute)
            )

        line = re.sub(r'URI="([^"]+)"', repl_uri, line)

        # Bare URI line (common for variant playlists and segments).
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            absolute = urljoin(current_url, stripped)
            if _allowed_upstream(absolute):
                line = "/admin/hls/{}/resource?u={}".format(
                    sid, _b64e(absolute)
                )

        out.append(line)

    return "\n".join(out) + ("\n" if text.endswith("\n") else "")

def _serve_upstream_response(resp, content_type=None):
    excluded = {
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "server",
        "date",
    }

    headers = {}
    for k, v in resp.headers.items():
        if k.lower() not in excluded:
            headers[k] = v

    if content_type:
        headers["Content-Type"] = content_type

    # HLS clients need these response headers.
    headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Headers"] = "Range, Authorization, Content-Type"
    headers["Access-Control-Expose-Headers"] = "Content-Length, Content-Range, Accept-Ranges"
    headers["Cache-Control"] = "no-store"

    def generate():
        try:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    yield chunk
        finally:
            resp.close()

    return Response(
        stream_with_context(generate()),
        status=resp.status_code,
        headers=headers,
    )


    if not isinstance(body, dict) or not body.get("success"):
        return jsonify(body), status

    stream_data = body.get("data") or {}
    upstream_token = stream_data.get("token")
    upstream_master = stream_data.get("stream_url")

    if not upstream_token or not upstream_master:
        return jsonify({
            "success": False,
            "message": "رد تشغيل الفيديو ناقص: token أو stream_url غير موجود"
        }), 502

    if not _allowed_upstream(upstream_master):
        return jsonify({
            "success": False,
            "message": "رابط الـ master غير مسموح به من الـ proxy"
        }), 502

    sid = _create_hls_session(video_id, stream_data)

    # Never return the upstream JWT to the browser.
    return jsonify({
        "success": True,
        "data": {
            "video_id": stream_data.get("video_id"),
            "session_id": stream_data.get("session_id"),
            "expires_in": stream_data.get("expires_in"),
            "poster_url": f"/admin/hls/{sid}/poster",
            "stream_url": f"/admin/hls/{sid}/master.m3u8",
            "heartbeat_url": f"/admin/hls/{sid}/heartbeat",
        }
    })

@app.route("/admin/video/<int:video_id>/play", methods=["GET", "OPTIONS"])
def admin_play_video(video_id):
    if request.method == "OPTIONS":
        return ("", 204)

    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    body, status = coursatk_post(f"/video/{video_id}/stream-weave/play")
    if status != 200:
        return jsonify(body), status

    if not isinstance(body, dict) or not body.get("success"):
        return jsonify(body), status

    stream_data = body.get("data") or {}
    upstream_token = stream_data.get("token")
    upstream_master = stream_data.get("stream_url")

    if not upstream_token or not upstream_master:
        return jsonify({
            "success": False,
            "message": "رد تشغيل الفيديو ناقص: token أو stream_url غير موجود"
        }), 502

    if not _allowed_upstream(upstream_master):
        return jsonify({
            "success": False,
            "message": "رابط الـ master غير مسموح به من الـ proxy"
        }), 502

    sid = _create_hls_session(video_id, stream_data)

    # لا نُرجع JWT الخاص بـ Stream-Weave إلى المتصفح.
    return jsonify({
        "success": True,
        "data": {
            "video_id": stream_data.get("video_id"),
            "session_id": stream_data.get("session_id"),
            "expires_in": stream_data.get("expires_in"),
            "poster_url": f"/admin/hls/{sid}/poster",
            "stream_url": f"/admin/hls/{sid}/master.m3u8",
            "heartbeat_url": f"/admin/hls/{sid}/heartbeat",
            "end_url": f"/admin/hls/{sid}/end",
        }
    })

@app.route("/admin/hls/<sid>/master.m3u8", methods=["GET", "OPTIONS"])
def admin_hls_master(sid):
    if request.method == "OPTIONS":
        return ("", 204)

    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    sess = _get_hls_session(sid)
    if not sess:
        return jsonify({"success": False, "message": "جلسة الفيديو انتهت"}), 410

    # Reconstruct the API master URL from the video id.
    video_id = sess["videoId"]
    upstream_url = (
        f"{STREAM_WEAVE_BASE}/api/v1/videos/"
        f"{video_id}/stream/master.m3u8"
    )

    try:
        resp = _upstream_get(upstream_url, sess["token"], stream=False)
        if resp.status_code != 200:
            return Response(
                resp.content,
                status=resp.status_code,
                content_type=resp.headers.get(
                    "Content-Type", "text/plain; charset=utf-8"
                ),
            )

        text = resp.text
        rewritten = _rewrite_playlist(text, sid, upstream_url)

        return Response(
            rewritten,
            status=200,
            content_type="application/vnd.apple.mpegurl",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store",
            },
        )
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Upstream error: {e}"}), 502

@app.route("/admin/hls/<sid>/resource", methods=["GET", "OPTIONS"])
def admin_hls_resource(sid):
    if request.method == "OPTIONS":
        return ("", 204)

    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    sess = _get_hls_session(sid)
    if not sess:
        return jsonify({"success": False, "message": "جلسة الفيديو انتهت"}), 410

    encoded = request.args.get("u", "")
    if not encoded:
        return jsonify({"success": False, "message": "الرابط مفقود"}), 400

    try:
        upstream_url = _b64d(encoded)
    except Exception:
        return jsonify({"success": False, "message": "رابط غير صالح"}), 400

    if not _allowed_upstream(upstream_url):
        return jsonify({"success": False, "message": "Upstream غير مسموح"}), 403

    # For media playlists, rewrite again so their nested segment URLs
    # also stay inside our proxy.
    try:
        resp = _upstream_get(upstream_url, sess["token"], stream=False)

        if resp.status_code != 200:
            return _serve_upstream_response(resp)

        content_type = (resp.headers.get("Content-Type") or "").lower()
        looks_like_playlist = (
            upstream_url.lower().endswith(".m3u8")
            or "mpegurl" in content_type
            or resp.text.lstrip().startswith("#EXTM3U")
        )

        if looks_like_playlist:
            rewritten = _rewrite_playlist(
                resp.text, sid, upstream_url
            )
            resp.close()
            return Response(
                rewritten,
                status=200,
                content_type="application/vnd.apple.mpegurl",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Cache-Control": "no-store",
                },
            )

        return _serve_upstream_response(resp)

    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Upstream error: {e}"}), 502

@app.route("/admin/hls/<sid>/poster", methods=["GET", "OPTIONS"])
def admin_hls_poster(sid):
    if request.method == "OPTIONS":
        return ("", 204)

    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    sess = _get_hls_session(sid)
    if not sess:
        return jsonify({"success": False, "message": "جلسة الفيديو انتهت"}), 410

    url = f"{STREAM_WEAVE_BASE}/api/v1/videos/{sess['videoId']}/poster"

    try:
        resp = _upstream_get(url, sess["token"], stream=True)
        return _serve_upstream_response(resp)
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Upstream error: {e}"}), 502

@app.route("/admin/hls/<sid>/heartbeat", methods=["POST", "OPTIONS"])
def admin_hls_heartbeat(sid):
    if request.method == "OPTIONS":
        return ("", 204)

    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    sess = _get_hls_session(sid)
    if not sess:
        return jsonify({"success": False, "message": "جلسة الفيديو انتهت"}), 410

    if not sess.get("sessionId") or not sess.get("token"):
        return jsonify({"success": False, "message": "بيانات الجلسة ناقصة"}), 500

    body, status = stream_weave_request(
        "POST",
        f"/api/v1/playback/session/{sess['sessionId']}/heartbeat",
        token=sess["token"]
    )
    return jsonify(body), status

@app.route("/admin/hls/<sid>/end", methods=["POST", "OPTIONS"])
def admin_hls_end(sid):
    if request.method == "OPTIONS":
        return ("", 204)

    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    sess = HLS_SESSIONS.pop(sid, None)
    if not sess:
        return jsonify({"success": True})

    if sess.get("sessionId") and sess.get("token"):
        body, status = stream_weave_request(
            "POST",
            f"/api/v1/playback/session/{sess['sessionId']}/end",
            token=sess["token"]
        )
        return jsonify(body), status

    return jsonify({"success": True})

@app.route("/video/stream-weave/heartbeat", methods=["POST"])
def video_heartbeat():
    """بيحافظ على الـ session اللي مع stream-weave"""
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    data = request.get_json(silent=True) or {}
    session_id = data.get("sessionId")
    token = data.get("token")
    
    if not session_id or not token:
        return jsonify({"success": False, "message": "sessionId و token مطلوبين"}), 400

    # طلب heartbeat لـ stream-weave
    body, status = stream_weave_request(
        "POST",
        f"/playback/session/{session_id}/heartbeat",
        token=token
    )
    
    return jsonify(body), status


@app.route("/video/stream-weave/m3u8", methods=["GET"])
def video_m3u8():
    """جلب الـ M3U8 playlist"""
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    video_id = request.args.get("videoId")
    token = request.args.get("token")
    
    if not video_id or not token:
        return jsonify({"success": False, "message": "videoId و token مطلوبين"}), 400

    body, status = stream_weave_request(
        "GET",
        f"/videos/{video_id}/stream/master.m3u8",
        token=token
    )
    
    if status != 200:
        return jsonify({"success": False, "message": "ما قدرش نجيب الـ playlist"}), status
    
    # لو كانت الرد ده M3U8 text
    if isinstance(body, str):
        return body, 200, {'Content-Type': 'application/vnd.apple.mpegurl'}
    
    return jsonify(body), status


@app.route("/video/stream-weave/key", methods=["GET"])
def video_key():
    """جلب مفتاح فك التشفير"""
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    video_id = request.args.get("videoId")
    token = request.args.get("token")
    
    if not video_id or not token:
        return jsonify({"success": False, "message": "videoId و token مطلوبين"}), 400

    body, status = stream_weave_request(
        "GET",
        f"/videos/{video_id}/key",
        token=token
    )
    
    return jsonify(body) if status != 200 else (body, 200, {'Content-Type': 'application/octet-stream'})


# =========================================================
# الطالب: كل طلبات المحتوى (بروكسي كامل - التوكن الحقيقي مايتشافش خالص)
# =========================================================
@app.route("/subjects/<int:year_id>", methods=["GET"])
def get_subjects(year_id):
    if not get_valid_session(request):
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    body, status = coursatk_get(f"/user/subjects/{year_id}")
    return jsonify(body), status


@app.route("/subjects/<int:subject_id>/teachers", methods=["GET"])
def get_teachers(subject_id):
    if not get_valid_session(request):
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    body, status = coursatk_get(f"/user/subjects/{subject_id}/teachers")
    return jsonify(body), status


@app.route("/teachers/<int:teacher_id>/chapters", methods=["GET"])
def get_chapters(teacher_id):
    if not get_valid_session(request):
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    body, status = coursatk_get(f"/user/teachers/{teacher_id}/chapters")
    return jsonify(body), status


@app.route("/chapters/<int:chapter_id>/lectures", methods=["GET"])
def get_lectures(chapter_id):
    if not get_valid_session(request):
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    body, status = coursatk_get(f"/user/chapters/{chapter_id}/lectures")
    return jsonify(body), status


@app.route("/lectures/<int:lecture_id>/content", methods=["GET"])
def get_lecture_content(lecture_id):
    if not get_valid_session(request):
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    body, status = coursatk_get(f"/user/lectures/{lecture_id}/content")
    return jsonify(body), status


@app.route("/video/<int:video_id>/platforms", methods=["GET"])
def get_video_platforms(video_id):
    if not get_valid_session(request):
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    body, status = coursatk_get(f"/video/{video_id}/platforms")
    return jsonify(body), status


# =========================================================
# الأدمن: تحديث توكن كورساتك
# =========================================================
@app.route("/admin/token", methods=["GET"])
def admin_get_token():
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    config = db.reference(NODE_CONFIG).get() or {}
    return jsonify({"success": True, "token": config.get("token", "")})


@app.route("/admin/token", methods=["POST"])
def admin_update_token():
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    db.reference(NODE_CONFIG).set({"token": token, "updatedAt": int(time.time())})
    return jsonify({"success": True})


# =========================================================
# الأدمن: فحص الاتصال
# =========================================================
@app.route("/admin/ping", methods=["GET", "OPTIONS"])
def admin_ping():
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    token = get_coursatk_token()
    return jsonify({
        "success": True,
        "coursatk_token_saved": bool(token),
        "token_length": len(token) if token else 0
    })


# =========================================================
# الأدمن: إدارة الطلاب
# =========================================================
@app.route("/admin/students", methods=["GET"])
def admin_list_students():
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return jsonify({"success": True, "students": db.reference(NODE_STUDENTS).get() or {}})


@app.route("/admin/students", methods=["POST"])
def admin_add_student():
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()
    name = data.get("name", "").strip()
    max_devices = int(data.get("maxDevices", 1))

    if not code or len(code) != 6 or not code.isdigit():
        return jsonify({"success": False, "message": "الكود لازم يكون 6 أرقام"}), 400
    if not name:
        return jsonify({"success": False, "message": "لازم تحط اسم الطالب"}), 400

    students = db.reference(NODE_STUDENTS).get() or {}
    for info in students.values():
        if info.get("code") == code:
            return jsonify({"success": False, "message": "الكود ده مستخدم بالفعل"}), 400

    student_id = str(int(time.time() * 1000))
    db.reference(f"{NODE_STUDENTS}/{student_id}").set({
        "code": code,
        "name": name,
        "maxDevices": max_devices,
        "devices": {},
        "active": True,
        "createdAt": int(time.time())
    })
    return jsonify({"success": True, "id": student_id})


@app.route("/admin/students/<student_id>", methods=["PUT"])
def admin_update_student(student_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401

    data = request.get_json(silent=True) or {}
    ref = db.reference(f"{NODE_STUDENTS}/{student_id}")
    existing = ref.get()
    if not existing:
        return jsonify({"success": False, "message": "الطالب مش موجود"}), 404

    updated = {**existing}
    if "code" in data:
        updated["code"] = str(data["code"]).strip()
    if "name" in data:
        updated["name"] = data["name"].strip()
    if "maxDevices" in data:
        updated["maxDevices"] = int(data["maxDevices"])
    if "active" in data:
        updated["active"] = bool(data["active"])

    ref.set(updated)
    return jsonify({"success": True})


@app.route("/admin/students/<student_id>", methods=["DELETE"])
def admin_delete_student(student_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    db.reference(f"{NODE_STUDENTS}/{student_id}").delete()
    return jsonify({"success": True})


@app.route("/admin/students/<student_id>/reset-devices", methods=["POST"])
def admin_reset_devices(student_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    ref = db.reference(f"{NODE_STUDENTS}/{student_id}")
    if not ref.get():
        return jsonify({"success": False, "message": "الطالب مش موجود"}), 404
    ref.child("devices").set({})
    return jsonify({"success": True})


@app.route("/admin/students/<student_id>/devices/<device_id>", methods=["PUT"])
def admin_update_device(student_id, device_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    data = request.get_json(silent=True) or {}
    device_ref = db.reference(f"{NODE_STUDENTS}/{student_id}/devices/{device_id}")
    existing = device_ref.get()
    if not existing:
        return jsonify({"success": False, "message": "الجهاز مش موجود"}), 404
    updated = existing if isinstance(existing, dict) else {}
    if "blocked" in data:
        updated["blocked"] = bool(data["blocked"])
    device_ref.set(updated)
    return jsonify({"success": True})


@app.route("/admin/students/<student_id>/devices/<device_id>", methods=["DELETE"])
def admin_delete_device(student_id, device_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    db.reference(f"{NODE_STUDENTS}/{student_id}/devices/{device_id}").delete()
    return jsonify({"success": True})


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "سيرفر كورساتك شغال"})


# =========================================================
# الأدمن: إنشاء جلسة تشغيل من Coursatk
# =========================================================


# =========================================================
# اختبار سريع مباشر (بالباسورد بس، من غير تسجيل دخول أو PIN)
# =========================================================
@app.route("/admin/subjects/<int:year_id>", methods=["GET", "OPTIONS"])
def admin_debug_subjects(year_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return debug_subjects(year_id)


@app.route("/debug/subjects/<int:year_id>", methods=["GET"])
def debug_subjects(year_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_get(f"/user/subjects/{year_id}")
    return jsonify(body), status


@app.route("/admin/subjects/<int:subject_id>/teachers", methods=["GET", "OPTIONS"])
def admin_debug_teachers(subject_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return debug_teachers(subject_id)


@app.route("/debug/subjects/<int:subject_id>/teachers", methods=["GET"])
def debug_teachers(subject_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_get(f"/user/subjects/{subject_id}/teachers")
    return jsonify(body), status


@app.route("/admin/teachers/<int:teacher_id>/chapters", methods=["GET", "OPTIONS"])
def admin_debug_chapters(teacher_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return debug_chapters(teacher_id)


@app.route("/debug/teachers/<int:teacher_id>/chapters", methods=["GET"])
def debug_chapters(teacher_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_get(f"/user/teachers/{teacher_id}/chapters")
    return jsonify(body), status


@app.route("/admin/chapters/<int:chapter_id>/lectures", methods=["GET", "OPTIONS"])
def admin_debug_lectures(chapter_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return debug_lectures(chapter_id)


@app.route("/debug/chapters/<int:chapter_id>/lectures", methods=["GET"])
def debug_lectures(chapter_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_get(f"/user/chapters/{chapter_id}/lectures")
    return jsonify(body), status


@app.route("/admin/lectures/<int:lecture_id>/content", methods=["GET", "OPTIONS"])
def admin_debug_content(lecture_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return debug_content(lecture_id)


@app.route("/debug/lectures/<int:lecture_id>/content", methods=["GET"])
def debug_content(lecture_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_get(f"/user/lectures/{lecture_id}/content")
    return jsonify(body), status


@app.route("/admin/video/<int:video_id>/platforms", methods=["GET", "OPTIONS"])
def admin_debug_video_platforms(video_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    return debug_video_platforms(video_id)


@app.route("/debug/video/<int:video_id>/platforms", methods=["GET"])
def debug_video_platforms(video_id):
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_get(f"/video/{video_id}/platforms")
    return jsonify(body), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
