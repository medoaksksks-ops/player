# Durosak Plus API — Phase 1

السيرفر ده طبقة بين الموقع وFirestore:

Browser → Node.js API → Firestore

## الملفات

- `server.js` — السيرفر والـ API.
- `package.json` — المكتبات وأوامر التشغيل.
- `README.md` — طريقة التشغيل.

## تشغيل محلي

```bash
npm install
npm start
```

## Firebase

السيرفر يحتاج Firebase service account حتى يقرأ Firestore.

### Railway

أضف Environment Variable باسم:

`FIREBASE_SERVICE_ACCOUNT_JSON`

وقيمته تكون **محتوى JSON كامل** لحساب خدمة Firebase، وليس رابط الملف.

بديل محلي:

`FIREBASE_SERVICE_ACCOUNT_FILE=./service-account.json`

لا ترفع `service-account.json` إلى GitHub.

## اختبار السيرفر

```text
GET /
GET /health
```

إذا Firebase مضبوط:

```text
GET /api/firestore/اسم_الكوليكشن
GET /api/firestore/اسم_الكوليكشن/ID
GET /api/content?collection=اسم_الكوليكشن
```

## ملاحظة مهمة

النسخة الحالية مفتوحة عمدًا للاختبار، لذلك أي شخص يستطيع استدعاء الـ API إذا عرف الرابط.

قبل اعتمادها للإنتاج سنضيف:
- Authentication / session validation
- Authorization
- تحديد الـ collections والحقول المسموح بها
- Rate limiting
- CORS مقيد على دومين الموقع
- منع القراءة العامة العشوائية
- Logging ومراقبة الأخطاء
- Cache مناسب للمحتوى

وكذلك سنحوّل الـ endpoints من `collection` عام إلى endpoints مخصصة لتطبيق Durosak، مثل:

`GET /api/materials`

`GET /api/materials/:materialId/teachers`

`GET /api/lectures/:lectureId/content`

وده أفضل وأأمن من فتح Firestore بالكامل عبر API.
