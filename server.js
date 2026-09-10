/**
 * server.js
 * VERSION: 1.0.0
 *
 * سيرفر شخصي: بيتابع حسابات/هاشتاجات تيك توك وانستجرام بشكل دوري (cron)
 * ويحفظ الجديد في feed.json، ويعرضه كـ API للفرونت (فيد عمودي autoplay).
 */

require('dotenv').config();
const express = require('express');
const cron = require('node-cron');
const config = require('./config.json');
const fetcher = require('./lib/fetcher');
const db = require('./lib/db');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- مهمة الاكتشاف الدورية ----------
async function discoverOnce() {
  console.log('[discover] بدء جولة اكتشاف جديدة...');
  const max = config.max_items_per_source || 20;

  const sources = [];
  for (const u of config.tiktok.accounts || []) {
    sources.push({ platform: 'tiktok', list: () => fetcher.listTikTokUser(u, max) });
  }
  for (const h of config.tiktok.hashtags || []) {
    sources.push({ platform: 'tiktok', list: () => fetcher.listTikTokHashtag(h, max) });
  }
  for (const u of config.instagram.accounts || []) {
    sources.push({ platform: 'instagram', list: () => fetcher.listInstagramUserReels(u, max) });
  }

  let newCount = 0;
  for (const source of sources) {
    try {
      const entries = await source.list();
      for (const entry of entries) {
        const added = db.addIfNew({
          id: entry.id,
          platform: source.platform,
          title: entry.title,
          permalink: entry.url,
        });
        if (added) newCount++;
      }
    } catch (err) {
      console.error(`[discover] فشل مصدر (${source.platform}):`, err.message);
    }
  }
  console.log(`[discover] انتهت الجولة — ${newCount} عنصر جديد.`);
}

// شغّل جولة اكتشاف فور تشغيل السيرفر
discoverOnce();

// جدولة دورية حسب config.json
const intervalMin = config.fetch_interval_minutes || 15;
cron.schedule(`*/${intervalMin} * * * *`, discoverOnce);

// ---------- API ----------

// الفيد المخزّن (بيانات أساسية بس، سريع)
app.get('/api/feed', (req, res) => {
  const limit = Math.min(Number(req.query.limit || 30), 100);
  res.json({ items: db.getFeed(limit) });
});

// حل رابط تشغيل مباشر لفيديو معيّن وقت الطلب (لأن الروابط بتنتهي بسرعة)
app.get('/api/resolve', async (req, res) => {
  const permalink = req.query.url;
  if (!permalink) return res.status(400).json({ error: 'missing url query param' });
  try {
    const [info, streamUrl] = await Promise.all([
      fetcher.getVideoInfo(permalink),
      fetcher.getDirectStreamUrl(permalink),
    ]);
    res.json({ ...info, stream_url: streamUrl });
  } catch (err) {
    res.status(502).json({ error: 'resolve_failed', message: err.message });
  }
});

// تشغيل جولة اكتشاف يدوياً وقت ما تحب (بدل الانتظار للجدولة)
app.post('/api/discover-now', async (req, res) => {
  await discoverOnce();
  res.json({ ok: true });
});

app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`reels-site v1.0.0 running on http://localhost:${PORT}`);
  console.log(`متابعة: tiktok(${(config.tiktok.accounts||[]).length} حساب, ${(config.tiktok.hashtags||[]).length} هاشتاج) | instagram(${(config.instagram.accounts||[]).length} حساب)`);
});
    
