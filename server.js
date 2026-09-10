/**
 * fb-scraper — server.js
 * VERSION: 1.0.0
 *
 * سيرفر شخصي بيستخدم كوكيز حسابك عشان يجيب بوستات/ريلز عامة ويعرضها كـ JSON.
 * ده للاستخدام الشخصي بس، حساب واحد، ومحتاج ضبط مستمر لأن فيسبوك بيغيّر الـ HTML/JSON بتاعه.
 */

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- إعداد الكوكيز والهيدرز ----------
// حط الكوكيز في ملف .env في متغير FB_COOKIE بنفس صيغة "key=value; key2=value2"
const FB_COOKIE = process.env.FB_COOKIE || '';

const MOBILE_UA =
  'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';

function client() {
  return axios.create({
    headers: {
      'User-Agent': MOBILE_UA,
      Cookie: FB_COOKIE,
      'Accept-Language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    timeout: 20000,
    validateStatus: () => true, // نتعامل مع أي status code يدوي
  });
}

// ---------- استخراج روابط الفيديو من HTML (تقنية شائعة) ----------
// فيسبوك بيحط روابط الفيديو الحقيقية جوه <script> tags كـ JSON مُهرّب (escaped).
// بندور على الحقول دي بالـ regex بدل ما نعتمد على تحليل DOM كامل.
function extractVideoUrls(html) {
  const results = {};

  // الجودة المنخفضة (sd) - ده اللي هنفضله دايماً
  const sdMatch = html.match(/"playable_url":"([^"]+)"/);
  if (sdMatch) results.sd = sdMatch[1].replace(/\\\//g, '/').replace(/\\u0025/g, '%');

  // الجودة العالية (hd) - بنجيبها بس للمقارنة، مش هنستخدمها افتراضياً
  const hdMatch = html.match(/"playable_url_quality_hd":"([^"]+)"/);
  if (hdMatch) results.hd = hdMatch[1].replace(/\\\//g, '/').replace(/\\u0025/g, '%');

  return results;
}

// ---------- 1) الفيد الرئيسي: بنجيب روابط البوستات/الريلز منه ----------
app.get('/api/feed', async (req, res) => {
  try {
    const c = client();
    const resp = await c.get('https://mbasic.facebook.com/?locale=ar_AR');

    if (resp.status !== 200) {
      return res.status(502).json({
        error: 'facebook_returned_non_200',
        status: resp.status,
        hint: 'ممكن الكوكيز منتهية أو محتاجة تحديث. جرب /api/raw?path=/ عشان تشوف الرد الخام.',
      });
    }

    const $ = cheerio.load(resp.data);
    const items = [];

    // mbasic بيحط كل بوست جوه عنصر يحتوي رابط "permalink" أو "story.php" أو "/videos/" أو "/reel/"
    $('a').each((_, el) => {
      const href = $(el).attr('href') || '';
      if (
        href.includes('story.php') ||
        href.includes('/permalink') ||
        href.includes('/videos/') ||
        href.includes('/reel/')
      ) {
        const type = href.includes('/reel/')
          ? 'reel'
          : href.includes('/videos/')
          ? 'video'
          : 'post';
        items.push({
          type,
          url: 'https://mbasic.facebook.com' + href,
          text: $(el).text().trim().slice(0, 100),
        });
      }
    });

    res.json({ count: items.length, items });
  } catch (err) {
    res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// ---------- 2) بوست أو فيديو معيّن بالتفصيل ----------
app.get('/api/item', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'missing url query param' });

  try {
    const c = client();
    // بنستخدم m.facebook.com هنا (مش mbasic) لأنه بيحمل الـ JSON بتاع الفيديو جوه الصفحة
    const mUrl = targetUrl.replace('mbasic.facebook.com', 'm.facebook.com');
    const resp = await c.get(mUrl);

    if (resp.status !== 200) {
      return res.status(502).json({ error: 'facebook_returned_non_200', status: resp.status });
    }

    const html = resp.data;
    const $ = cheerio.load(html);

    const text = $('meta[property="og:description"]').attr('content') || '';
    const image = $('meta[property="og:image"]').attr('content') || '';
    const video = extractVideoUrls(html);

    res.json({
      url: targetUrl,
      text,
      image,
      // بنفضل الجودة المنخفضة زي ما طلبت، ولو مش موجودة نرجع اللي متاح
      video_url: video.sd || video.hd || null,
      quality: video.sd ? 'sd' : video.hd ? 'hd' : null,
    });
  } catch (err) {
    res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

// ---------- 3) endpoint تشخيصي: يرجعلك الـ HTML الخام عشان تعدل الـ selectors بنفسك ----------
app.get('/api/raw', async (req, res) => {
  const path = req.query.path || '/';
  try {
    const c = client();
    const resp = await c.get('https://mbasic.facebook.com' + path);
    res.status(200).type('text/plain').send(resp.data);
  } catch (err) {
    res.status(500).json({ error: 'fetch_failed', message: err.message });
  }
});

app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`fb-scraper v1.0.0 running on http://localhost:${PORT}`);
  console.log(FB_COOKIE ? '✓ FB_COOKIE loaded' : '✗ WARNING: FB_COOKIE is empty — set it in .env');
});
          
