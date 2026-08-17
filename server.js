// server.js
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const CryptoJS = require('crypto-js');
const fs = require('fs-extra');
const path = require('path');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

// =========================================================
// 1. MIDDLEWARE
// =========================================================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// =========================================================
// 2. WEBSOCKET FOR REAL-TIME PROGRESS
// =========================================================

const wss = new WebSocketServer({ port: 8080 });
const clients = new Map();

wss.on('connection', (ws) => {
    const id = Date.now().toString();
    clients.set(id, ws);
    console.log(`[WS] ✅ Client connected: ${id}`);

    ws.on('close', () => {
        clients.delete(id);
        console.log(`[WS] ❌ Client disconnected: ${id}`);
    });
});

function sendProgress(videoId, progress, status, details) {
    const message = JSON.stringify({
        videoId,
        progress,
        status,
        details,
        timestamp: Date.now()
    });

    for (const [id, ws] of clients) {
        if (ws.readyState === 1) {
            ws.send(message);
        }
    }
}

// =========================================================
// 3. HELPERS
// =========================================================

function hexToBytes(hex) {
    const pairs = hex.match(/../g);
    if (!pairs) throw new Error("Invalid HEX value");
    return new Uint8Array(pairs.map(x => parseInt(x, 16)));
}

function bytesToUint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (Array.isArray(data)) return new Uint8Array(data);
    return new Uint8Array(data);
}

async function fetchText(url, token) {
    const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 30000
    });
    return response.data;
}

async function fetchBuffer(url, token) {
    const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'arraybuffer',
        timeout: 60000
    });
    return response.data;
}

// =========================================================
// 4. فك تشفير المفتاح (زي ما بيحصل في المتصفح)
// =========================================================

function decryptPlaybackKey(wrappedKey, videoId) {
    // دي محاكاة لعملية فك التشفير اللي بتحصل في المتصفح
    // في الواقع بتحتاج مكتبة Stream-Weave لكن مش متاحة على Node.js
    // هنحاكيها باستخدام CryptoJS
    
    try {
        // تحويل المفتاح المغلف لـ WordArray
        const keyData = CryptoJS.enc.Hex.parse(
            Array.from(new Uint8Array(wrappedKey))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')
        );
        
        // في الواقع: هنا بتحصل عملية فك تشفير معقدة باستخدام video_id
        // هنعمل محاكاة بسيطة للاختبار
        const mockKey = CryptoJS.SHA256(videoId.toString() + 'streamweave');
        return { key: new Uint8Array(mockKey.words.map(w => w & 0xFF)) };
    } catch (e) {
        console.error('[SW] فك المفتاح فشل:', e);
        throw new Error('Failed to decrypt playback key');
    }
}

// =========================================================
// 5. الوظيفة الرئيسية للتحميل
// =========================================================

async function downloadVideo(videoId, token, wsClient = null) {
    console.log(`[SW] 🚀 بدء تحميل الفيديو ${videoId}`);
    sendProgress(videoId, 0, 'جاري تجهيز الجلسة...', 'جاري...');

    // 5.1 جلب جلسة تشغيل جديدة
    const playResponse = await axios.post(
        `https://api.coursatk.online/api/v1/video/${videoId}/stream-weave/play`,
        {},
        {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            },
            timeout: 30000
        }
    );

    const data = playResponse.data;
    if (!data?.success || !data?.data?.token || !data?.data?.stream_url) {
        throw new Error('فشل الحصول على جلسة تشغيل');
    }

    const session = data.data;
    const streamToken = session.token;
    const videoIdSW = session.video_id;
    const masterUrl = session.stream_url;

    console.log(`[SW] ✅ جلسة تشغيل: ${session.session_id}`);
    sendProgress(videoId, 5, 'جلسة تشغيل جاهزة', `Session: ${session.session_id}`);

    // 5.2 جلب Master Playlist
    sendProgress(videoId, 10, 'جاري جلب قائمة التشغيل...', 'Master playlist');
    const masterText = await fetchText(masterUrl, streamToken);
    const masterLines = masterText.split('\n').map(l => l.trim());

    const variantLine = masterLines.find(l => l && !l.startsWith('#'));
    if (!variantLine) throw new Error('Variant playlist not found');
    const variantUrl = new URL(variantLine, masterUrl).href;

    // 5.3 جلب Variant Playlist
    sendProgress(videoId, 15, 'جاري جلب التفاصيل...', 'Variant playlist');
    const variantText = await fetchText(variantUrl, streamToken);
    const lines = variantText.split('\n').map(l => l.trim());

    // 5.4 استخراج المفتاح
    const keyLine = lines.find(l => l.startsWith('#EXT-X-KEY:'));
    if (!keyLine) throw new Error('EXT-X-KEY missing');

    const keyUriMatch = keyLine.match(/URI="([^"]+)"/);
    const ivMatch = keyLine.match(/IV=0x([0-9a-fA-F]{32})/);

    if (!keyUriMatch) throw new Error('Key URI missing');
    if (!ivMatch) throw new Error('IV missing');

    const keyUrl = new URL(keyUriMatch[1], variantUrl).href;
    const iv = hexToBytes(ivMatch[1]);

    // 5.5 جلب المفتاح المغلف
    sendProgress(videoId, 20, 'جاري جلب المفتاح...', 'Encryption key');
    const keyResponse = await axios.get(keyUrl, {
        headers: { Authorization: `Bearer ${streamToken}` },
        responseType: 'arraybuffer',
        timeout: 30000
    });

    const wrappedKey = new Uint8Array(keyResponse.data);

    // 5.6 فك المفتاح (محاكاة)
    sendProgress(videoId, 25, 'جاري فك المفتاح...', 'Unwrapping key');
    const keyResult = decryptPlaybackKey(wrappedKey, videoIdSW);
    const aesKey = keyResult.key;

    if (!aesKey || aesKey.length !== 16) {
        throw new Error('Invalid AES-128 key');
    }

    // 5.7 قائمة المقاطع
    let segments = lines
        .filter(l => l && !l.startsWith('#') && l.startsWith('http'))
        .map(l => new URL(l, variantUrl).href);

    if (segments.length === 0) throw new Error('No segments found');

    console.log(`[SW] 📊 عدد المقاطع: ${segments.length}`);
    sendProgress(videoId, 30, `جاري تحميل ${segments.length} مقطع...`, 'جاري...');

    // 5.8 تحميل وفك تشفير المقاطع
    const allData = [];
    let totalSize = 0;
    const tempDir = path.join(__dirname, 'temp', videoId.toString());
    await fs.ensureDir(tempDir);

    for (let i = 0; i < segments.length; i++) {
        const num = i + 1;
        const percent = 30 + ((num / segments.length) * 60);

        sendProgress(
            videoId,
            Math.round(percent),
            `المقطع ${num}/${segments.length}`,
            `${Math.round((num / segments.length) * 100)}%`
        );

        // تحميل المقطع
        const encrypted = await fetchBuffer(segments[i], streamToken);

        // فك التشفير (محاكاة)
        // في الواقع: لازم تستخدم مكتبة AES-CBC أو مكتبة Stream-Weave
        // هنعمل محاكاة بسيطة للاختبار
        const decrypted = new Uint8Array(encrypted);
        allData.push(decrypted);
        totalSize += decrypted.length;

        // حفظ المقطع مؤقتاً
        await fs.writeFile(
            path.join(tempDir, `segment_${String(num).padStart(4, '0')}.ts`),
            decrypted
        );

        console.log(`[SW] ✅ مقطع ${num}/${segments.length} تم`);
    }

    // 5.9 دمج المقاطع
    sendProgress(videoId, 92, 'جاري دمج المقاطع...', 'Merging...');
    const outputFile = path.join(__dirname, 'downloads', `coursatk-${videoId}.ts`);
    await fs.ensureDir(path.join(__dirname, 'downloads'));

    // دمج الملفات
    const files = await fs.readdir(tempDir);
    files.sort();
    const writeStream = fs.createWriteStream(outputFile);

    for (const file of files) {
        const data = await fs.readFile(path.join(tempDir, file));
        writeStream.write(data);
    }

    writeStream.end();

    // تنظيف الملفات المؤقتة
    await fs.remove(tempDir);

    sendProgress(videoId, 98, 'جاري تجهيز الملف للتحميل...', 'Finalizing...');

    // 5.10 إنشاء رابط التحميل
    const downloadUrl = `/download/${videoId}`;

    console.log(`[SW] ✅ تم تحميل الفيديو: ${videoId}`);
    console.log(`[SW] 📦 الحجم: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);

    sendProgress(videoId, 100, '✅ اكتمل التحميل!', 'Ready for download');

    return {
        videoId,
        downloadUrl,
        size: totalSize,
        segments: segments.length,
        path: outputFile
    };
}

// =========================================================
// 6. API ENDPOINTS
// =========================================================

// 6.1 طلب التحميل من الموبايل
app.post('/api/download', async (req, res) => {
    try {
        const { token, video_id } = req.body;

        if (!token) {
            return res.status(400).json({ error: '❌ التوكن مطلوب' });
        }
        if (!video_id) {
            return res.status(400).json({ error: '❌ رقم الفيديو مطلوب' });
        }

        console.log(`[API] 📥 طلب تحميل فيديو ${video_id}`);

        // بدأ التحميل في الخلفية (async)
        const result = await downloadVideo(video_id, token);

        res.json({
            success: true,
            videoId: video_id,
            downloadUrl: result.downloadUrl,
            size: result.size,
            segments: result.segments
        });

    } catch (error) {
        console.error('[API] ❌ فشل:', error);
        res.status(500).json({
            error: error.message || 'فشل التحميل',
            success: false
        });
    }
});

// 6.2 تحميل الملف النهائي
app.get('/download/:videoId', async (req, res) => {
    try {
        const { videoId } = req.params;
        const filePath = path.join(__dirname, 'downloads', `coursatk-${videoId}.ts`);

        if (!await fs.pathExists(filePath)) {
            return res.status(404).json({ error: 'الملف غير موجود' });
        }

        res.download(filePath, `coursatk-${videoId}.ts`, (err) => {
            if (err) {
                console.error('[DOWNLOAD] خطأ:', err);
            }
        });

    } catch (error) {
        console.error('[DOWNLOAD] ❌ فشل:', error);
        res.status(500).json({ error: error.message });
    }
});

// 6.3 حالة التحميل
app.get('/api/status/:videoId', async (req, res) => {
    try {
        const { videoId } = req.params;
        const filePath = path.join(__dirname, 'downloads', `coursatk-${videoId}.ts`);
        const exists = await fs.pathExists(filePath);

        res.json({
            videoId,
            exists,
            downloadUrl: exists ? `/download/${videoId}` : null,
            size: exists ? (await fs.stat(filePath)).size : 0
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 6.4 قائمة الفيديوهات المحملة
app.get('/api/list', async (req, res) => {
    try {
        const files = await fs.readdir(path.join(__dirname, 'downloads'));
        const videos = [];

        for (const file of files) {
            if (file.endsWith('.ts')) {
                const match = file.match(/coursatk-(\d+)\.ts/);
                if (match) {
                    const stats = await fs.stat(path.join(__dirname, 'downloads', file));
                    videos.push({
                        videoId: parseInt(match[1]),
                        filename: file,
                        size: stats.size,
                        created: stats.birthtime
                    });
                }
            }
        }

        res.json({ videos });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================================================
// 7. لوحة التحكم (HTML)
// =========================================================

app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>لوحة تحميل كورساتك</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: system-ui, sans-serif;
                background: #0a0a0a;
                color: #fff;
                padding: 20px;
                min-height: 100vh;
            }
            .container { max-width: 800px; margin: 0 auto; }
            h1 {
                color: #4CAF50;
                text-align: center;
                margin-bottom: 30px;
                font-size: 24px;
            }
            .card {
                background: #1a1a1a;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 20px;
                border: 1px solid #333;
            }
            .card h2 {
                font-size: 16px;
                color: #aaa;
                margin-bottom: 10px;
            }
            input, button {
                width: 100%;
                padding: 12px;
                border-radius: 8px;
                border: none;
                font-size: 16px;
                box-sizing: border-box;
            }
            input {
                background: #222;
                color: #fff;
                border: 1px solid #333;
                margin-bottom: 10px;
            }
            button {
                background: #4CAF50;
                color: #fff;
                font-weight: bold;
                cursor: pointer;
                transition: 0.2s;
            }
            button:hover { background: #45a049; }
            button:disabled {
                background: #555;
                cursor: not-allowed;
            }
            #progress-container {
                display: none;
                margin-top: 15px;
            }
            #progress-bar {
                width: 0%;
                height: 8px;
                background: #4CAF50;
                border-radius: 4px;
                transition: width 0.3s;
            }
            #progress-text {
                display: flex;
                justify-content: space-between;
                margin-top: 5px;
                font-size: 13px;
                color: #888;
            }
            #status-text {
                color: #aaa;
                font-size: 14px;
                margin-top: 8px;
            }
            .video-item {
                display: flex;
                justify-content: space-between;
                padding: 10px 0;
                border-bottom: 1px solid #222;
                font-size: 14px;
            }
            .video-item .id { color: #4CAF50; font-weight: bold; }
            .video-item .size { color: #888; }
            .video-item a {
                color: #4CAF50;
                text-decoration: none;
                font-weight: bold;
            }
            .video-item a:hover { text-decoration: underline; }
            .log {
                background: #0a0a0a;
                padding: 10px;
                border-radius: 6px;
                font-family: monospace;
                font-size: 12px;
                max-height: 200px;
                overflow-y: auto;
                color: #aaa;
                border: 1px solid #222;
            }
            .log .success { color: #4CAF50; }
            .log .error { color: #f44336; }
            .log .info { color: #2196F3; }
            .log .warning { color: #FF9800; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📥 لوحة تحميل كورساتك</h1>

            <div class="card">
                <h2>⬇️ تحميل فيديو جديد</h2>
                <input id="video-id" type="number" placeholder="أدخل رقم الفيديو (مثال: 19947)">
                <button id="download-btn">🚀 تحميل الفيديو</button>

                <div id="progress-container">
                    <div id="progress-bar"></div>
                    <div id="progress-text">
                        <span id="progress-percent">0%</span>
                        <span id="progress-details">جاري...</span>
                    </div>
                    <div id="status-text">⏳ في انتظار البدء...</div>
                </div>
            </div>

            <div class="card">
                <h2>📂 الفيديوهات المحملة</h2>
                <div id="video-list">
                    <div style="color: #666; text-align: center; padding: 20px;">جاري التحميل...</div>
                </div>
            </div>

            <div class="card">
                <h2>📝 سجل التحميل</h2>
                <div id="log-container" class="log">
                    <div class="info">⏳ في انتظار بدء التحميل...</div>
                </div>
            </div>
        </div>

        <script>
            let ws = null;
            let currentVideoId = null;

            // =========================================================
            // WEBSOCKET CONNECTION
            // =========================================================

            function connectWS() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = \`\${protocol}//\${window.location.hostname}:8080\`;
                
                ws = new WebSocket(wsUrl);

                ws.onopen = () => {
                    addLog('info', '✅ متصل بالسيرفر');
                };

                ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        updateProgress(data);
                    } catch (e) {
                        console.error('WebSocket error:', e);
                    }
                };

                ws.onclose = () => {
                    addLog('warning', '⚠️ فقد الاتصال بالسيرفر، محاولة إعادة الاتصال...');
                    setTimeout(connectWS, 2000);
                };

                ws.onerror = () => {
                    addLog('error', '❌ خطأ في الاتصال');
                };
            }

            // =========================================================
            // UPDATE UI
            // =========================================================

            function updateProgress(data) {
                const { videoId, progress, status, details } = data;

                if (currentVideoId && videoId !== currentVideoId) return;

                const container = document.getElementById('progress-container');
                const bar = document.getElementById('progress-bar');
                const percent = document.getElementById('progress-percent');
                const detailsSpan = document.getElementById('progress-details');
                const statusText = document.getElementById('status-text');

                container.style.display = 'block';
                bar.style.width = progress + '%';
                percent.textContent = progress + '%';
                detailsSpan.textContent = details || status;
                statusText.textContent = status;

                if (progress >= 100) {
                    statusText.textContent = '✅ تم التحميل!';
                    statusText.style.color = '#4CAF50';
                    document.getElementById('download-btn').disabled = false;
                    document.getElementById('download-btn').textContent = '🚀 تحميل فيديو جديد';
                    loadVideoList();
                }
            }

            function addLog(type, message) {
                const container = document.getElementById('log-container');
                const colors = {
                    success: '#4CAF50',
                    error: '#f44336',
                    info: '#2196F3',
                    warning: '#FF9800'
                };
                const time = new Date().toLocaleTimeString();
                const div = document.createElement('div');
                div.innerHTML = \`<span style="color: #666;">[\${time}]</span> <span style="color: \${colors[type] || '#aaa'};">\${message}</span>\`;
                container.appendChild(div);
                container.scrollTop = container.scrollHeight;
            }

            // =========================================================
            // LOAD VIDEO LIST
            // =========================================================

            async function loadVideoList() {
                try {
                    const response = await fetch('/api/list');
                    const data = await response.json();

                    const container = document.getElementById('video-list');

                    if (!data.videos || data.videos.length === 0) {
                        container.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">📭 لا يوجد فيديوهات محملة</div>';
                        return;
                    }

                    let html = '';
                    for (const video of data.videos) {
                        const size = (video.size / 1024 / 1024).toFixed(2);
                        html += \`
                            <div class="video-item">
                                <span class="id">🎬 #\${video.videoId}</span>
                                <span class="size">\${size} MB</span>
                                <a href="/download/\${video.videoId}" target="_blank">⬇️ تحميل</a>
                            </div>
                        \`;
                    }
                    container.innerHTML = html;

                } catch (e) {
                    console.error('Error loading videos:', e);
                }
            }

            // =========================================================
            // DOWNLOAD BUTTON
            // =========================================================

            document.getElementById('download-btn').addEventListener('click', async () => {
                const input = document.getElementById('video-id');
                const videoId = parseInt(input.value);

                if (!videoId || videoId < 1) {
                    alert('أدخل رقم فيديو صحيح');
                    return;
                }

                // نحتاج التوكن من localStorage بتاع كورساتك
                // هنطلب من المستخدم يدخله لو مش موجود
                let token = localStorage.getItem('coursatk_token');
                if (!token) {
                    token = prompt('أدخل توكن كورساتك (ممكن تجيبه من console.log في صفحة كورساتك)');
                    if (!token) return;
                    localStorage.setItem('coursatk_token', token);
                }

                const btn = document.getElementById('download-btn');
                btn.disabled = true;
                btn.textContent = '⏳ جاري التحميل...';
                currentVideoId = videoId;

                const container = document.getElementById('progress-container');
                container.style.display = 'block';
                document.getElementById('progress-bar').style.width = '0%';
                document.getElementById('progress-percent').textContent = '0%';
                document.getElementById('status-text').textContent = '⏳ بدء التحميل...';
                document.getElementById('status-text').style.color = '#aaa';

                addLog('info', \`🚀 بدء تحميل الفيديو #\${videoId}\`);

                try {
                    const response = await fetch('/api/download', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token, video_id: videoId })
                    });

                    const data = await response.json();

                    if (!data.success) {
                        throw new Error(data.error || 'فشل التحميل');
                    }

                    addLog('success', \`✅ تم تحميل الفيديو #\${videoId}\`);
                    addLog('info', \`📦 الحجم: \${(data.size / 1024 / 1024).toFixed(2)} MB\`);
                    addLog('info', \`📊 المقاطع: \${data.segments}\`);

                    // فتح رابط التحميل
                    window.open(data.downloadUrl, '_blank');

                    btn.disabled = false;
                    btn.textContent = '🚀 تحميل فيديو جديد';

                } catch (e) {
                    addLog('error', \`❌ فشل: \${e.message}\`);
                    alert('❌ فشل التحميل: ' + e.message);
                    btn.disabled = false;
                    btn.textContent = '🚀 تحميل فيديو جديد';
                }
            });

            // =========================================================
            // INIT
            // =========================================================

            connectWS();
            loadVideoList();

            // تحديث القائمة كل 30 ثانية
            setInterval(loadVideoList, 30000);

            console.log('==============================================');
            console.log('[SW] 🔥 لوحة التحكم جاهزة');
            console.log('[SW] 🌐 افتح على http://localhost:3000');
            console.log('[SW] 🔌 WebSocket على ws://localhost:8080');
            console.log('==============================================');
        </script>
    </body>
    </html>
    `);
});

// =========================================================
// 8. بدء السيرفر
// =========================================================

app.listen(PORT, () => {
    console.log(`==============================================`);
    console.log(`[SW] 🔥 سيرفر كورساتك شغال`);
    console.log(`[SW] 🌐 http://localhost:${PORT}`);
    console.log(`[SW] 🔌 WebSocket على ws://localhost:8080`);
    console.log(`[SW] 📁 التحميلات في: /downloads`);
    console.log(`==============================================`);
});

// إنشاء المجلدات المطلوبة
fs.ensureDirSync(path.join(__dirname, 'downloads'));
fs.ensureDirSync(path.join(__dirname, 'temp'));