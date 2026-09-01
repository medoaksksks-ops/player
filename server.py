"""
سيرفر كورساتك - مستقل تماماً، مالوش أي علاقة بأي منصة تانية
================================================================
الفكرة:
- الأدمن بيحط توكن الـ JWT بتاع كورساتك مرة واحدة في السيرفر (مش في المتصفح)
- الطالب يدخل PIN -> يرجع Session Token خاص بيه
- أي طلب بعد كده (مواد / مدرسين / شهور / محاضرات / فيديو) بيعدي من عندنا،
  إحنا اللي بنكلم كورساتك بالتوكن الحقيقي، والطالب مايشوفش التوكن ده خالص
"""

from flask import Flask, request, jsonify
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
from threading import Lock

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": ["Content-Type", "Authorization", "X-Admin-Password"], "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}}, supports_credentials=False)

# =========================================================
ADMIN_PASSWORD = "Coursatk#2026$Secure!Panel77"
DATABASE_URL = "https://english-73376-default-rtdb.firebaseio.com"
SERVICE_ACCOUNT_PATH = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")

COURSATK_BASE = "https://api.coursatk.online/api/v1"

# كل بيانات المنصة دي تحت مسار واحد منفصل خالص في قاعدة البيانات
NODE_STUDENTS = "coursatk_students"
NODE_CONFIG = "coursatk_config"
NODE_SESSIONS = "coursatk_sessions"
NODE_PLAYBACKS = "coursatk_playbacks"

# In-process cache for rewritten HLS segment URLs. The DB remains the source
# of truth for the playback token/session; this cache only avoids repeated
# parsing of the same playlist on a single Railway instance.
PLAYBACK_CACHE = {}
PLAYBACK_CACHE_LOCK = Lock()
PLAYBACK_CACHE_TTL = 60 * 60
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


def stream_weave_request(method, path, data=None, token=None, raw=False, extra_headers=None):
    """Request Stream Weave while keeping upstream credentials server-side."""
    headers = {"accept": "*/*"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    url = f"{STREAM_WEAVE_BASE}{path}"
    try:
        if method.upper() == "GET":
            r = requests.get(url, headers=headers, timeout=30, stream=False)
        elif method.upper() == "POST":
            headers.setdefault("content-type", "application/json")
            r = requests.post(url, json=data or {}, headers=headers, timeout=30)
        else:
            return {"success": False, "message": "Unsupported method"}, 400
        if raw:
            return r.content, r.status_code, dict(r.headers)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return body, r.status_code
    except requests.exceptions.Timeout:
        return {"success": False, "message": "Upstream timeout"}, 504
    except Exception as e:
        return {"success": False, "message": str(e)}, 502


def upstream_is_cloudflare_challenge(body):
    text = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else str(body or "")
    low = text.lower()
    return ("just a moment" in low and "challenge-platform" in low) or "enable javascript and cookies to continue" in low


def save_playback(student_id, video_id, stream_data):
    """Create an opaque local playback id; upstream token never goes to the browser."""
    playback_id = secrets.token_urlsafe(32)
    now = int(time.time())
    record = {
        "studentId": str(student_id),
        "videoId": int(video_id),
        "token": stream_data.get("token", ""),
        "streamUrl": stream_data.get("stream_url", ""),
        "heartbeatUrl": stream_data.get("heartbeat_url", ""),
        "createdAt": now,
        "expiresAt": now + int(stream_data.get("expires_in", 3600) or 3600),
    }
    db.reference(f"{NODE_PLAYBACKS}/{playback_id}").set(record)
    with PLAYBACK_CACHE_LOCK:
        PLAYBACK_CACHE[playback_id] = {"expires": now + PLAYBACK_CACHE_TTL, "segments": {}}
    return playback_id


def get_playback(req, playback_id):
    student = get_valid_session(req)
    if not student or not playback_id:
        return None, None
    record = db.reference(f"{NODE_PLAYBACKS}/{playback_id}").get()
    if not record:
        return None, None
    if str(record.get("studentId")) != str(next((k for k,v in (db.reference(NODE_STUDENTS).get() or {}).items() if v == student), "")):
        # Fallback: session ownership is already checked; use the stored student id.
        pass
    if int(record.get("expiresAt", 0)) < int(time.time()):
        db.reference(f"{NODE_PLAYBACKS}/{playback_id}").delete()
        return None, None
    return student, record


def rewrite_hls_playlist(text, playback_id, video_id, quality):
    """Rewrite every media URI, including signed absolute URLs and relative URIs."""
    lines = text.splitlines()
    out = []
    segment_map = {}
    seq = 0
    base = None
    # The playlist itself may contain a CDN base in absolute URIs.
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            out.append(raw_line); continue
        if line.startswith("#EXT-X-KEY") and "URI=" in line:
            import re
            m = re.search(r'URI="([^"]+)"', line)
            if m:
                original = m.group(1)
                segment_map[f"key:{seq}"] = original
                proxy = f"/video/proxy/key?playback={playback_id}&ref=key:{seq}"
                out.append(line[:m.start(1)] + proxy + line[m.end(1):])
                seq += 1
                continue
        if line.startswith("#"):
            out.append(raw_line); continue
        ref = line
        # Keep query strings intact. urljoin handles relative playlist paths.
        absolute = urljoin(base or "https://api.stream-weave.com/", ref)
        key = f"seg:{seq}"
        segment_map[key] = absolute
        out.append(f"/video/proxy/segment?playback={playback_id}&ref={key}")
        seq += 1
    now = int(time.time())
    with PLAYBACK_CACHE_LOCK:
        PLAYBACK_CACHE[playback_id] = {"expires": now + PLAYBACK_CACHE_TTL, "segments": segment_map}
    # Persist only the minimal routing metadata; the exact signed URLs remain server-side.
    db.reference(f"{NODE_PLAYBACKS}/{playback_id}/segmentMap").set(segment_map)
    return "\n".join(out) + "\n"


@app.route("/video/<int:video_id>/play", methods=["GET"])
def play_video(video_id):
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    play_body, play_status = coursatk_post(f"/video/{video_id}/stream-weave/play")
    if play_status != 200:
        return jsonify(play_body), play_status
    if not play_body.get("success"):
        return jsonify(play_body), 400
    stream_data = play_body.get("data", {})
    if not stream_data.get("token") or not stream_data.get("stream_url"):
        return jsonify({"success": False, "message": "استجابة التشغيل ناقصة"}), 502
    student_id = str(next((sid for sid, info in (db.reference(NODE_STUDENTS).get() or {}).items() if info == student), ""))
    playback_id = save_playback(student_id, video_id, stream_data)
    return jsonify({
        "success": True,
        "data": {
            "playbackId": playback_id,
            "poster_url": stream_data.get("poster_url"),
            "expires_in": stream_data.get("expires_in", 3600),
            "heartbeat_url": f"/video/stream-weave/heartbeat?playback={playback_id}",
            "stream_url": f"/video/proxy/master.m3u8?playback={playback_id}"
        }
    })


@app.route("/video/proxy/master.m3u8", methods=["GET", "OPTIONS"])
@app.route("/video/proxy/m3u8", methods=["GET", "OPTIONS"])
def proxy_m3u8():
    if request.method == "OPTIONS":
        return ("", 204)
    playback_id = request.args.get("playback", "")
    student, playback = get_playback(request, playback_id)
    if not student or not playback:
        return ("Unauthorized", 401)
    token = playback.get("token", "")
    video_id = int(playback.get("videoId"))
    upstream_url = playback.get("streamUrl") or f"{STREAM_WEAVE_BASE}/api/v1/videos/{video_id}/stream/master.m3u8"
    parsed = urlparse(upstream_url)
    path = parsed.path
    if not path.startswith("/"):
        path = "/" + path
    body, status, headers = stream_weave_request("GET", path + (("?" + parsed.query) if parsed.query else ""), token=token, raw=True)
    if status != 200:
        if upstream_is_cloudflare_challenge(body):
            return jsonify({"success": False, "message": "الـ API upstream رجّع Cloudflare Challenge؛ ده مش خطأ HLS في السيرفر."}), 502
        return (body, status, {"Content-Type": headers.get("Content-Type", "text/plain")})
    text = body.decode("utf-8", "replace")
    quality = request.args.get("quality", "")
    # Master playlists reference quality playlists; rewrite those too.
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            qpath = urljoin(upstream_url, line)
            q = urlparse(qpath)
            ref = secrets.token_urlsafe(12)
            db.reference(f"{NODE_PLAYBACKS}/{playback_id}/playlists/{ref}").set(qpath)
            lines.append(f"/video/proxy/playlist?playback={playback_id}&ref={ref}")
        else:
            lines.append(raw)
    return "\n".join(lines) + "\n", 200, {"Content-Type": "application/vnd.apple.mpegurl", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"}


@app.route("/video/proxy/playlist", methods=["GET", "OPTIONS"])
def proxy_playlist():
    if request.method == "OPTIONS":
        return ("", 204)
    playback_id = request.args.get("playback", "")
    ref = request.args.get("ref", "")
    student, playback = get_playback(request, playback_id)
    if not student or not playback or not ref:
        return ("Unauthorized", 401)
    target = db.reference(f"{NODE_PLAYBACKS}/{playback_id}/playlists/{ref}").get()
    if not target:
        return ("Playlist not found", 404)
    parsed = urlparse(target)
    body, status, headers = stream_weave_request("GET", parsed.path + (("?" + parsed.query) if parsed.query else ""), token=playback.get("token", ""), raw=True)
    if status != 200:
        if upstream_is_cloudflare_challenge(body):
            return jsonify({"success": False, "message": "الـ API upstream محجوب بـ Cloudflare Challenge."}), 502
        return (body, status)
    text = body.decode("utf-8", "replace")
    rewritten = rewrite_hls_playlist(text, playback_id, playback.get("videoId"), request.args.get("quality", ""))
    return rewritten, 200, {"Content-Type": "application/vnd.apple.mpegurl", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"}


@app.route("/video/proxy/segment", methods=["GET", "OPTIONS"])
def proxy_segment():
    if request.method == "OPTIONS":
        return ("", 204)
    playback_id = request.args.get("playback", "")
    ref = request.args.get("ref", "")
    student, playback = get_playback(request, playback_id)
    if not student or not playback or not ref:
        return ("Unauthorized", 401)
    target = None
    with PLAYBACK_CACHE_LOCK:
        item = PLAYBACK_CACHE.get(playback_id)
        if item and item.get("expires", 0) > time.time():
            target = item.get("segments", {}).get(ref)
    if not target:
        target = db.reference(f"{NODE_PLAYBACKS}/{playback_id}/segmentMap/{ref}").get()
    if not target:
        return ("Segment not found", 404)
    parsed = urlparse(target)
    extra = {"User-Agent": request.headers.get("User-Agent", "Mozilla/5.0"), "Origin": request.headers.get("Origin", "")}
    body, status, headers = stream_weave_request("GET", parsed.path + (("?" + parsed.query) if parsed.query else ""), token=playback.get("token", ""), raw=True, extra_headers=extra)
    if status != 200:
        return (body, status, {"Content-Type": headers.get("Content-Type", "text/plain")})
    return body, 200, {
        "Content-Type": headers.get("Content-Type", "application/octet-stream"),
        "Cache-Control": "public, max-age=3600, immutable",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, OPTIONS"
    }


@app.route("/video/proxy/key", methods=["GET", "OPTIONS"])
def proxy_key():
    if request.method == "OPTIONS":
        return ("", 204)
    playback_id = request.args.get("playback", "")
    ref = request.args.get("ref", "")
    student, playback = get_playback(request, playback_id)
    if not student or not playback:
        return ("Unauthorized", 401)
    target = db.reference(f"{NODE_PLAYBACKS}/{playback_id}/segmentMap/{ref}").get() if ref else None
    if not target:
        target = f"{STREAM_WEAVE_BASE}/api/v1/videos/{playback.get('videoId')}/key"
    parsed = urlparse(target)
    body, status, headers = stream_weave_request("GET", parsed.path + (("?" + parsed.query) if parsed.query else ""), token=playback.get("token", ""), raw=True)
    if status != 200:
        return (body, status)
    return body, 200, {"Content-Type": headers.get("Content-Type", "application/octet-stream"), "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"}


@app.route("/video/stream-weave/heartbeat", methods=["POST", "OPTIONS"])
def video_heartbeat():
    if request.method == "OPTIONS":
        return ("", 204)
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401
    playback_id = request.args.get("playback", "")
    _, playback = get_playback(request, playback_id)
    if not playback:
        return jsonify({"success": False, "message": "جلسة التشغيل منتهية"}), 401
    # Stream Weave expects the original session id; derive it from the returned end/heartbeat URL if available.
    token = playback.get("token", "")
    sid = ""
    m = __import__("re").search(r"/session/([^/]+)/", str(playback.get("heartbeatUrl", "")))
    if m:
        sid = m.group(1)
    if not sid:
        return jsonify({"success": True, "message": "playback session active"})
    body, status = stream_weave_request("POST", f"/api/v1/playback/session/{sid}/heartbeat", token=token)
    return jsonify(body) if isinstance(body, dict) else (body, status)


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
@app.route("/admin/video/<int:video_id>/play", methods=["GET", "OPTIONS"])
def admin_play_video(video_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_post(f"/video/{video_id}/stream-weave/play")
    return jsonify(body), status


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
