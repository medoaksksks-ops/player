// server.js - الخادم الخلفي (Backend Proxy)
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const app = express();
const PORT = process.env.PORT || 3000;

// =========================================================
// 1. إعدادات الخادم
// =========================================================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'Accept', 'Origin', 'Referer', 'X-Requested-With'],
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// تحديد معدل الطلبات (100 طلب لكل دقيقة)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { success: false, message: 'تم تجاوز عدد الطلبات المسموحة، حاول بعد دقيقة' }
});
app.use('/api/', limiter);

// =========================================================
// 2. التوكن الثابت (مضمن)
// =========================================================
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo5MzUwOSwicm9sZSI6InN0dWRlbnQiLCJ1dWlkIjoiNWUzYWMwNGU3YTI5YmNiODUwN2Y1MzE3ZGRjMmM4ODYifQ.v1TphLydce3VzJGtKkW2E1hSlVptPoeRdPd82Za9Nrk';

// =========================================================
// 3. الوكيل الرئيسي - يعيد توجيه كل الطلبات
// =========================================================
app.all('/api/*', async (req, res) => {
  try {
    // بناء الرابط المستهدف
    const targetUrl = `https://api.coursatk.online${req.originalUrl}`;
    
    // تجهيز الهيدرز (نرسل كل الهيدرز الواردة مع التعديلات اللازمة)
    const headers = {
      'Authorization': `Bearer ${TOKEN}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Origin': 'https://coursatk.online',
      'Referer': 'https://coursatk.online/',
      'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en-US;q=0.7,en;q=0.6',
      'sec-ch-ua': '"Not;A=Brand";v="8", "Chromium";v="150", "Android WebView";v="150"',
      'sec-ch-ua-mobile': '?1',
      'sec-ch-ua-platform': '"Android"',
      'sec-fetch-site': 'same-site',
      'sec-fetch-mode': 'cors',
      'sec-fetch-dest': 'empty',
      'priority': 'u=1, i'
    };

    // إعدادات الطلب
    const config = {
      method: req.method,
      url: targetUrl,
      headers: headers,
      data: req.body,
      params: req.query,
      responseType: 'arraybuffer', // للتعامل مع الفيديوهات والمقاطع
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    };

    // تنفيذ الطلب
    const response = await axios(config);

    // تحديد نوع المحتوى من الرد الأصلي
    const contentType = response.headers['content-type'] || 'application/json';
    
    // إعداد الهيدرز للرد
    res.set({
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept, Origin, Referer, X-Requested-With',
      'Content-Type': contentType
    });

    // إرسال الرد
    res.status(response.status).send(response.data);

    console.log(`[PROXY] ✅ ${req.method} ${req.originalUrl} -> ${response.status}`);

  } catch (error) {
    console.error(`[PROXY] ❌ خطأ في ${req.originalUrl}:`, error.message);
    
    // التعامل مع أخطاء axios
    if (error.response) {
      const contentType = error.response.headers['content-type'] || 'application/json';
      res.set('Content-Type', contentType);
      res.status(error.response.status).send(error.response.data);
    } else {
      res.status(500).json({
        success: false,
        message: 'خطأ في الخادم الوكيل',
        error: error.message
      });
    }
  }
});

// =========================================================
// 4. تشغيل الخادم
// =========================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log('==============================================');
  console.log(`[PROXY] 🚀 خادم كورساتك الوكيل شغال على http://localhost:${PORT}`);
  console.log('[PROXY] 🔑 التوكن مضمن');
  console.log('[PROXY] 🌐 استخدم endpoint: http://localhost:3000/api/...');
  console.log('==============================================');
});
