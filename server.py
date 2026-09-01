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

app = Flask(__name__)
CORS(app)

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


@app.route("/video/proxy/m3u8", methods=["GET"])
def proxy_m3u8():
    """جلب M3U8 playlist وتعديل روابط القطع لتمرّ عبر السيرفر (Proxy)"""
    student = get_valid_session(request)
    if not student:
        return ("Unauthorized", 401)

    video_id = request.args.get("videoId")
    quality = request.args.get("quality", "1080")  # default 1080p
    token = request.args.get("token")
    
    if not video_id or not token:
        return ("Missing parameters", 400)

    # جلب M3U8 من Stream Weave
    body, status = stream_weave_request(
        "GET",
        f"/api/v1/videos/{video_id}/stream/{quality}/playlist.m3u8",
        token=token
    )
    
    if status != 200:
        return ("Failed to fetch playlist", status)
    
    if isinstance(body, str):
        # تعديل الـ M3U8 لتمرير الـ segments عبر السيرفر
        m3u8_content = body
        lines = m3u8_content.split('\n')
        modified_lines = []
        
        for line in lines:
            # لو كان الـ line فيه رابط cloudfrount (segment)
            if 'cloudfrount.shop' in line or 'cloud3.cloudfrount.shop' in line:
                # استخرج اسم الـ segment
                segment_name = line.split('/')[-1].split('?')[0]
                # غيّر الرابط ليمرّ عبر السيرفر
                modified_lines.append(f"/video/proxy/segment?videoId={video_id}&quality={quality}&name={segment_name}&token={token}")
            
            # لو كان KEY encryption path
            elif '#EXT-X-KEY' in line and '/api/v1/videos' in line:
                # عدّل مسار المفتاح
                modified_line = line.replace(
                    '/api/v1/videos/' + video_id + '/key',
                    f'/video/proxy/key?videoId={video_id}&token={token}'
                )
                modified_lines.append(modified_line)
            else:
                modified_lines.append(line)
        
        modified_m3u8 = '\n'.join(modified_lines)
        return modified_m3u8, 200, {'Content-Type': 'application/vnd.apple.mpegurl'}
    
    return body, status


@app.route("/video/proxy/segment", methods=["GET"])
def proxy_segment():
    """proxy لـ video segments - جلب القطعة من cloudfrount وإرجاعها للمشغل"""
    student = get_valid_session(request)
    if not student:
        return ("Unauthorized", 401)

    segment_name = request.args.get("name")
    video_id = request.args.get("videoId")
    quality = request.args.get("quality", "1080")
    token = request.args.get("token")
    
    if not segment_name or not video_id or not token:
        return ("Missing parameters", 400)

    # بناء الرابط الأصلي من cloudfrount
    segment_url = f"https://cloud3.cloudfrount.shop/c486a506f1d8/videos/{video_id}/{quality}/{segment_name}"
    
    try:
        # جلب الـ segment من cloudfrount
        response = requests.get(segment_url, timeout=30, stream=True)
        
        if response.status_code != 200:
            return ("Segment not found", 404)
        
        # إرجاع الـ segment للمشغل بنفس الـ headers
        return response.content, 200, {
            'Content-Type': response.headers.get('Content-Type', 'application/octet-stream'),
            'Content-Length': response.headers.get('Content-Length', ''),
            'Cache-Control': 'public, max-age=3600',
            'Access-Control-Allow-Origin': '*'
        }
    except requests.exceptions.Timeout:
        return ("Request timeout", 504)
    except Exception as e:
        return (f"Error: {str(e)}", 502)


@app.route("/video/proxy/key", methods=["GET"])
def proxy_key():
    """proxy لـ encryption key - جلب المفتاح من Stream Weave"""
    student = get_valid_session(request)
    if not student:
        return ("Unauthorized", 401)

    video_id = request.args.get("videoId")
    token = request.args.get("token")
    
    if not video_id or not token:
        return ("Missing parameters", 400)

    # جلب المفتاح من Stream Weave
    try:
        response = requests.get(
            f"https://api.stream-weave.com/api/v1/videos/{video_id}/key",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        
        if response.status_code != 200:
            return ("Key not found", 404)
        
        # إرجاع المفتاح مع الـ headers الصحيحة
        return response.content, 200, {
            'Content-Type': 'application/octet-stream',
            'Cache-Control': 'public, max-age=86400',
            'Access-Control-Allow-Origin': '*'
        }
    except requests.exceptions.Timeout:
        return ("Request timeout", 504)
    except Exception as e:
        return (f"Error: {str(e)}", 502)


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
