/**
 * lib/db.js
 * VERSION: 1.0.0
 *
 * تخزين بسيط بملف JSON — كافي لموقع شخصي، مفيش داعي لقاعدة بيانات كاملة دلوقتي.
 */

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'feed.json');

function load() {
  if (!fs.existsSync(DB_PATH)) return [];
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return [];
  }
}

function save(items) {
  fs.writeFileSync(DB_PATH, JSON.stringify(items, null, 2));
}

function addIfNew(item) {
  const items = load();
  if (items.some((i) => i.id === item.id && i.platform === item.platform)) {
    return false; // موجود بالفعل
  }
  items.unshift({ ...item, fetched_at: new Date().toISOString() });
  save(items);
  return true;
}

function getFeed(limit = 50) {
  return load()
    .sort((a, b) => new Date(b.fetched_at) - new Date(a.fetched_at))
    .slice(0, limit);
}

module.exports = { addIfNew, getFeed, load, save };
    
