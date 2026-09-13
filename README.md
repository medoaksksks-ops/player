# Naqal Backend — 3 Files

الباك إند ده معمول عشان موقع **نقّل** يعتمد على:

**Mobile → WebRTC DataChannel → Tablet**

والـ Railway server دوره الأساسي هو **Signaling** فقط.

## الملفات المطلوبة

```text
server.js
package.json
README.md
```

وده كل اللي تحتاجه في Repository منفصل للباك إند.

---

# 1) الرفع على GitHub

اعمل Repository جديد، وارفع الملفات الثلاثة كما هي:

```text
naqal-backend/
├── server.js
├── package.json
└── README.md
```

لا تحتاج `node_modules`.

---

# 2) تشغيله على Railway

في Railway:

1. New Project
2. Deploy from GitHub Repo
3. اختر Repository الخاص بالباك إند.
4. Railway سيقرأ `package.json`.
5. أمر التشغيل:

```bash
npm start
```

لا تضع Port ثابتًا في Railway؛ `server.js` يستخدم `process.env.PORT` تلقائيًا.

بعد التشغيل اختبر:

```text
https://YOUR-RAILWAY-DOMAIN/health
```

المفروض يرجع JSON قريب من:

```json
{
  "ok": true,
  "service": "naqal-signaling",
  "rooms": 0,
  "uptime": 123
}
```

---

# 3) ربط الموقع بالباك إند

في JavaScript الخاص بالواجهة:

```js
const socket = io("https://YOUR-RAILWAY-DOMAIN", {
  transports: ["websocket", "polling"]
});
```

## إنشاء كود

```js
socket.emit("create-room", {}, result => {
  if (result.ok) {
    console.log("CODE:", result.code);
  }
});
```

`result.code` هو الكود المكون من 6 أرقام الذي يظهر للمستخدم.

## التابلت يدخل الكود

```js
socket.emit("join-room", { code: "482731" }, result => {
  console.log(result);
});
```

بعد نجاح الانضمام سيصل للمرسل:

```js
socket.on("peer-joined", () => {
  // ابدأ WebRTC هنا
});
```

---

# 4) WebRTC والإشارة

الباك إند يدعم تمرير:

```js
socket.emit("signal", {
  type: "offer",
  data: pc.localDescription
});
```

والطرف الثاني يستقبل:

```js
socket.on("signal", async message => {
  // message.type
  // message.data
});
```

ثم يرسل `answer` بالطريقة نفسها.

يمكنك أيضًا تمرير ICE candidates عبر نفس حدث `signal`.

**السيرفر لا يحتفظ برسائل الإشارة بعد تمريرها.**

---

# 5) السرعة

أهم نقطة:

**لا ترسل الملفات إلى هذا السيرفر.**

لا تستخدم:

```text
POST /upload
```

ولا:

```text
FormData → Railway
```

ولا تخزن الملفات على Disk أو RAM في Node.

الطريقة الصحيحة للسرعة هي:

```text
الموبايل
   │
   │ WebRTC DataChannel
   │
   ▼
التابلت
```

السيرفر:

```text
Mobile ── signaling ──> Railway
Tablet ── signaling ──> Railway
```

ثم بعد إنشاء الاتصال:

```text
Mobile ═════ P2P WebRTC ═════ Tablet
```

وبالتالي حجم الملف لا يمر عبر Railway في الوضع المباشر.

---

# 6) مهم جدًا بخصوص "بدون إنترنت"

هناك فرق بين:

### نقل بدون رفع الملفات للإنترنت

نعم.

الملفات لا تحتاج أن تمر عبر Railway.

### تشغيل الكود الموجود على Railway

هنا الجهازان يحتاجان الوصول إلى Railway أثناء **مرحلة الاقتران/signaling**.

لو تريد:

```text
لا إنترنت إطلاقًا
+
كود 6 أرقام
+
نقل مباشر
```

فلا يمكن أن يكون Railway هو الـsignaling server في نفس الوقت.

في الحالة دي يجب تشغيل نفس `server.js` محليًا على شبكة الـWi-Fi/Hotspot.

---

# 7) هل السيرفر ده سريع؟

نعم، لأنه **ليس في مسار الملفات أصلًا**.

سرعة النقل تعتمد أساسًا على:

- Wi-Fi
- قوة الجهازين
- المتصفح
- WebRTC
- حجم الـchunks
- `bufferedAmount`
- جودة الاتصال المحلي

أما Node/Socket.IO هنا فبيتعامل مع رسائل صغيرة جدًا مثل:

```text
create room
join room
offer
answer
ICE
```

وليس ملفات الفيديو أو ZIP أو PDF.

---

# 8) إعداد الواجهة للسرعة

في الـfrontend استخدم DataChannel بإعداد مناسب:

```js
const channel = pc.createDataChannel("files", {
  ordered: true
});

channel.binaryType = "arraybuffer";
```

وأرسل الملفات كـchunks، مثل:

```js
const CHUNK_SIZE = 256 * 1024;
```

مع مراقبة:

```js
channel.bufferedAmount
```

وعدم ضخ البيانات أسرع من قدرة WebRTC على تصريف الـbuffer.

للموبايلات والتابلتات، لا تفترض أن Chunk ضخم جدًا سيكون أسرع دائمًا؛ `64–256 KB` نقطة بداية جيدة ثم يمكن ضبطها حسب الأداء.

---

# 9) TURN / STUN

هذا الباك إند **لا يحتوي TURN server**.

وده مقصود.

لو الجهازين على نفس Wi-Fi أو Hotspot، نريد اتصالًا محليًا مباشرًا قدر الإمكان.

لو احتجت تشغيل النقل بين شبكات مختلفة، يمكن إضافة STUN/TURN إلى `RTCPeerConnection` في **الواجهة**.

لكن:

**TURN Relay يعني أن بيانات الملف قد تمر عبر خادم TURN، وبالتالي لا يعود النقل محليًا بالكامل.**

---

# 10) الأمان

الكود يمنع دخول جهاز ثالث إلى نفس الغرفة بعد وجود peer.

الكود عشوائي 6 أرقام.

الغرفة تنتهي بعد فترة عدم نشاط.

لا يوجد:

- File storage
- Database
- Upload endpoint
- File proxy
- حفظ للملفات

السيرفر يعمل كـsignaling فقط.

---

# الخلاصة

الـarchitecture المقترح:

```text
              ┌──────────────────┐
              │ Railway           │
              │ Naqal Signaling   │
              │ Socket.IO         │
              └────────┬─────────┘
                       │
                 كود 6 أرقام
                       │
             ┌─────────┴─────────┐
             │                   │
        📱 الموبايل          📱 التابلت
             │                   │
             └════ WebRTC ═══════┘
                  DataChannel
                   الملفات
```

**Railway = اقتران وإشارة فقط.**

**WebRTC = نقل الملفات.**

وده أفضل تصميم لو هدفك نقل ملفات كبيرة بسرعة بدون جعل السيرفر عنق زجاجة.
