# APK Cloud Runner — Backend Only

كل الباك إند موجود في ملفات مباشرة داخل نفس الفولدر، بدون `public/` أو `runner/`.

## الملفات
- `server.js` — السيرفر + Android Runner mode في نفس الملف
- `package.json`
- `Dockerfile`
- `railway.toml`
- `.env.example`
- `.dockerignore`
- `README.md`

## Railway
ارفع **كل الملفات الموجودة في الفولدر** إلى نفس الـ GitHub repository.
ثم Deploy من GitHub على Railway.

Variables:
- `RUNNER_TOKEN` = سر طويل عشوائي

## Android Runner
نفس `server.js` يعمل كـ Runner عند تشغيل:

```bash
RUNNER_MODE=1 BACKEND_URL=https://YOUR-RAILWAY-DOMAIN RUNNER_TOKEN=YOUR_TOKEN node server.js
```

لو ADB على جهاز Android بعيد:
```bash
ADB_SERIAL=IP:5555
```

الموقع/الواجهة متوقفة حاليًا حسب طلبك؛ التركيز هنا على الباك إند والـ Runner فقط.

مهم: Railway يشغّل Node server، بينما تشغيل Android يحتاج جهاز/سيرفر عليه Android وADB.
