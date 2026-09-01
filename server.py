"""
سيرفر كورساتك - مستقل تماماً، مالوش أي علاقة بأي منصة تانية
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

app = Flask(__name__)
CORS(app)

# =========================================================
ADMIN_PASSWORD = "Coursatk#2026$Secure!Panel77"
DATABASE_URL = "https://english-73376-default-rtdb.firebaseio.com"
SERVICE_ACCOUNT_PATH = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")

COURSATK_BASE = "https://api.coursatk.online/api/v1"

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
    """بيبعت طلب لكورساتك بالتوكن المخزن عندنا"""
    token = get_coursatk_token()
    if not token:
        return {"success": False, "message": "التوكن لسه متسجلش في اللوحة"}, 500

    headers = {
        "authorization": f"Bearer {token}",
        "accept": "*/*",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        r = requests.get(f"{COURSATK_BASE}{path}", headers=headers, timeout=15)
        
        # 🔥 كشف Cloudflare challenge
        if "text/html" in r.headers.get("content-type", ""):
            return {
                "success": False, 
                "message": "Cloudflare protection - جرب خلال دقيقة",
                "cloudflare": True
            }, 403
        
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return body, r.status_code
        
    except Exception as e:
        return {"success": False, "message": str(e)}, 502


def coursatk_post(path, data=None):
    """بيبعت POST request لكورساتك بالتوكن المخزن عندنا"""
    token = get_coursatk_token()
    if not token:
        return {"success": False, "message": "التوكن لسه متسجلش في اللوحة"}, 500

    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "accept": "*/*",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        r = requests.post(f"{COURSATK_BASE}{path}", json=data or {}, headers=headers, timeout=15)
        
        # 🔥 كشف Cloudflare challenge
        if "text/html" in r.headers.get("content-type", ""):
            return {
                "success": False, 
                "message": "Cloudflare protection - جرب خلال دقيقة",
                "cloudflare": True
            }, 403
        
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
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    play_body, play_status = coursatk_post(f"/video/{video_id}/stream-weave/play")
    
    if play_status != 200:
        return jsonify(play_body), play_status
    
    if not play_body.get("success"):
        return jsonify(play_body), 400
    
    stream_data = play_body.get("data", {})
    stream_token = stream_data.get("token")
    
    if not stream_token:
        return jsonify({"success": False, "message": "ما قدرش نحصل على الـ token"}), 500
    
    return jsonify({
        "success": True,
        "data": stream_data,
        "streamToken": stream_token
    })


@app.route("/video/stream-weave/heartbeat", methods=["POST"])
def video_heartbeat():
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    data = request.get_json(silent=True) or {}
    session_id = data.get("sessionId")
    token = data.get("token")
    
    if not session_id or not token:
        return jsonify({"success": False, "message": "sessionId و token مطلوبين"}), 400

    body, status = stream_weave_request(
        "POST",
        f"/playback/session/{session_id}/heartbeat",
        token=token
    )
    
    return jsonify(body), status


# =========================================================
# Stream Weave HLS proxy chain
# =========================================================

def _hls_response(body, status=200):
    return body, status, {"Content-Type": "application/vnd.apple.mpegurl; charset=utf-8"}


def _stream_weave_get(url, token):
    if not url.startswith(STREAM_WEAVE_BASE + "/"):
        return None, 400

    try:
        r = requests.get(
            url,
            headers={"authorization": f"Bearer {token}", "accept": "*/*"},
            timeout=20
        )
        return r, r.status_code
    except Exception:
        return None, 502


@app.route("/video/stream-weave/m3u8", methods=["GET"])
def video_m3u8():
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    from urllib.parse import quote, urljoin

    video_id = request.args.get("videoId", "").strip()
    token = request.args.get("token", "").strip()

    if not video_id or not token:
        return jsonify({"success": False, "message": "videoId و token مطلوبين"}), 400

    r, status = _stream_weave_get(
        f"{STREAM_WEAVE_BASE}/api/v1/videos/{video_id}/stream/master.m3u8",
        token
    )

    if not r or status != 200:
        return jsonify({"success": False, "message": "ما قدرش نجيب الـ master playlist"}), status

    out = []
    for line in r.text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            variant_url = urljoin(r.url, s)
            out.append(
                "/video/stream-weave/playlist?url="
                + quote(variant_url, safe="")
                + "&token="
                + quote(token, safe="")
            )
        else:
            out.append(line)

    return _hls_response("\n".join(out) + "\n")


@app.route("/video/stream-weave/playlist", methods=["GET"])
def video_variant_playlist():
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    from urllib.parse import quote, urljoin
    import re

    url = request.args.get("url", "").strip()
    token = request.args.get("token", "").strip()

    if not url or not token:
        return jsonify({"success": False, "message": "url و token مطلوبين"}), 400

    if not url.startswith(STREAM_WEAVE_BASE + "/"):
        return jsonify({"success": False, "message": "عنوان غير مسموح"}), 400

    r, status = _stream_weave_get(url, token)
    if not r or status != 200:
        return jsonify({"success": False, "message": "ما قدرش نجيب الـ playlist"}), status

    out = []

    for line in r.text.splitlines():
        s = line.strip()

        if s.startswith("#EXT-X-KEY:"):
            m = re.search(r'URI="([^"]+)"', line)
            if m:
                key_url = urljoin(r.url, m.group(1))
                proxy_key = (
                    "/video/stream-weave/key-proxy?url="
                    + quote(key_url, safe="")
                    + "&token="
                    + quote(token, safe="")
                )
                line = line.replace(m.group(1), proxy_key)
            out.append(line)

        elif s and not s.startswith("#"):
            segment_url = urljoin(r.url, s)
            out.append(
                "/video/stream-weave/segment?url="
                + quote(segment_url, safe="")
                + "&token="
                + quote(token, safe="")
            )
        else:
            out.append(line)

    return _hls_response("\n".join(out) + "\n")


@app.route("/video/stream-weave/key-proxy", methods=["GET"])
def video_key_proxy():
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    url = request.args.get("url", "").strip()
    token = request.args.get("token", "").strip()

    if not url or not token:
        return jsonify({"success": False, "message": "url و token مطلوبين"}), 400

    if not url.startswith(STREAM_WEAVE_BASE + "/api/v1/videos/") or not url.endswith("/key"):
        return jsonify({"success": False, "message": "عنوان المفتاح غير مسموح"}), 400

    try:
        r = requests.get(
            url,
            headers={"authorization": f"Bearer {token}", "accept": "*/*"},
            timeout=20
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 502

    return (
        r.content,
        r.status_code,
        {
            "Content-Type": r.headers.get("Content-Type", "application/octet-stream"),
            "Cache-Control": "no-store"
        }
    )


@app.route("/video/stream-weave/segment", methods=["GET"])
def video_segment_proxy():
    student = get_valid_session(request)
    if not student:
        return jsonify({"success": False, "message": "سجل دخول تاني"}), 401

    from urllib.parse import urlparse
    from flask import Response

    url = request.args.get("url", "").strip()
    token = request.args.get("token", "").strip()

    if not url or not token:
        return jsonify({"success": False, "message": "url و token مطلوبين"}), 400

    parsed = urlparse(url)

    # السماح بأي hostname من floravon.online
    if parsed.scheme != "https" or not parsed.hostname.endswith(".floravon.online"):
        return jsonify({"success": False, "message": "مصدر الفيديو غير مسموح"}), 400

    try:
        headers = {
            "authorization": f"Bearer {token}",
            "accept": "*/*",
            "referer": "https://coursatk.online/",
            "origin": "https://coursatk.online",
            "accept-encoding": "identity",
            "user-agent": request.headers.get("User-Agent", "Mozilla/5.0")
        }
        
        r = requests.get(url, headers=headers, timeout=30, stream=True)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 502

    if r.status_code != 200:
        return (
            r.content,
            r.status_code,
            {"Content-Type": r.headers.get("Content-Type", "application/octet-stream")}
        )

    return Response(
        r.iter_content(chunk_size=64 * 1024),
        status=200,
        content_type=r.headers.get("Content-Type", "video/mp2t"),
        headers={"Cache-Control": "no-store", "Accept-Ranges": "bytes"}
    )


# =========================================================
# الطالب: كل طلبات المحتوى
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
# الأدمن
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


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "سيرفر كورساتك شغال"})


@app.route("/admin/video/<int:video_id>/play", methods=["GET", "OPTIONS"])
def admin_play_video(video_id):
    if request.method == "OPTIONS":
        return ("", 204)
    if not check_admin(request):
        return jsonify({"success": False, "message": "باسورد غلط"}), 401
    body, status = coursatk_post(f"/video/{video_id}/stream-weave/play")
    return jsonify(body), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)