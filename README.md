# Durosak Notification Watcher

خدمة Node.js تعمل 24/7 على Railway وتراقب Firestore لحظيًا.

## الوظيفة

عند إضافة مستند جديد إلى أي Collection موجودة في:

`NOTIFICATION_COLLECTIONS`

سيتم حذفه مباشرة من Firestore.

## مهم

بشكل افتراضي:

`DELETE_EXISTING_ON_STARTUP=false`

يعني عند تشغيل السيرفر لأول مرة أو بعد Restart، لن يتم حذف المستندات القديمة الموجودة بالفعل. سيتم حذف الإشعارات التي تُضاف بعد بدء المراقبة فقط.

إذا أردت حذف الموجود أيضًا عند بداية التشغيل، غيّرها إلى:

`DELETE_EXISTING_ON_STARTUP=true`

## 1) رفع الملفات

ارفع:

- `server.js`
- `package.json`

إلى Repository على GitHub، ثم اربطه بـ Railway.

## 2) Environment Variables في Railway

أضف:

### FIREBASE_PROJECT_ID
قيمة Project ID من Firebase.

### FIREBASE_CLIENT_EMAIL
قيمة `client_email` من Service Account JSON.

### FIREBASE_PRIVATE_KEY
قيمة `private_key` كاملة من Service Account JSON.

لو Railway حفظها وفيها `\n`، الكود يحولها تلقائيًا إلى أسطر حقيقية.

### NOTIFICATION_COLLECTIONS
اسم Collection الإشعارات.

مثال:

`notifications`

ولو عندك أكثر من Collection:

`notifications,announcements,alerts,messages`

### DELETE_EXISTING_ON_STARTUP
اتركها:

`false`

## 3) Firebase Service Account

من Firebase/Google Cloud أنشئ Service Account له صلاحية مناسبة للوصول إلى Firestore، ثم استخدم بيانات الاعتماد كـ Environment Variables.

لا تضع Service Account JSON داخل GitHub ولا داخل HTML ولا ترسله لأي شخص.

## 4) التشغيل

Railway سيشغل:

`npm start`

والخدمة ستفتح Endpoint:

`/`

و:

`/health`

مثال:

`https://YOUR-RAILWAY-DOMAIN.up.railway.app/health`

إذا رجعت:

`"status": "healthy"`

فالسيرفر شغال.

## 5) ملاحظات

- الخدمة تستخدم Firestore realtime listener.
- لا تحتاج صفحة HTML مفتوحة.
- Railway هو الذي يبقي الخدمة تعمل.
- إذا حدث Restart، سيعيد الاتصال تلقائيًا.
- حذف المستند يتم من Firestore نفسه.
