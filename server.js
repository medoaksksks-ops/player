const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');

// اختياري للتطوير المحلي فقط
try {
    require('dotenv').config();
} catch (e) {
    // Railway توفر المتغيرات تلقائياً
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ============================================
// إحصائيات وسجلات التحميلات
// ============================================

let downloadStats = {
    totalDownloads: 0,
    activeDownloads: 0,
    totalDataProcessed: 0,
    logs: []
};

function addLog(videoId, status, message, dataSize = 0) {
    const log = {
        timestamp: new Date().toISOString(),
        videoId,
        status,
        message,
        dataSize
    };
    downloadStats.logs.unshift(log);
    // احتفظ بـ 50 لوج فقط
    if (downloadStats.logs.length > 50) {
        downloadStats.logs.pop();
    }
}

// ============================================
// فك تشفير AES-128 CBC
// ============================================

function decryptAES128CBC(encryptedBuffer, key, iv) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    let decrypted = decipher.update(encryptedBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}

// ============================================
// تحميل القطع من الـ URL
// ============================================

async function downloadSegment(url, token, timeout = 30000) {
    try {
        const response = await axios.get(url, {
            headers: {
                'Authorization': `Bearer ${token}`
            },
            responseType: 'arraybuffer',
            timeout: timeout
        });
        return Buffer.from(response.data);
    } catch (error) {
        console.error(`❌ خطأ في تحميل القطعة: ${url}`, error.message);
        throw error;
    }
}

// ============================================
// تحويل Buffer لـ key وـ IV
// ============================================

function bufferFromData(data) {
    if (Buffer.isBuffer(data)) return data;
    if (typeof data === 'string') return Buffer.from(data, 'base64');
    if (Array.isArray(data)) return Buffer.from(data);
    return data;
}

// ============================================
// Route: Dashboard - لوحة التحكم
// ============================================

app.get('/dashboard', (req, res) => {
    const uptime = process.uptime();
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);
    
    const html = `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Coursatk Proxy Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
                color: #fff;
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                text-align: center;
                margin-bottom: 40px;
            }
            .header h1 {
                font-size: 32px;
                margin-bottom: 5px;
                color: #4CAF50;
            }
            .header p {
                color: #aaa;
                font-size: 14px;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }
            .stat-card {
                background: rgba(76,175,80,0.1);
                border: 1px solid rgba(76,175,80,0.3);
                border-radius: 10px;
                padding: 20px;
                text-align: center;
            }
            .stat-card h3 {
                color: #4CAF50;
                font-size: 12px;
                text-transform: uppercase;
                margin-bottom: 10px;
                letter-spacing: 1px;
            }
            .stat-card .value {
                font-size: 28px;
                font-weight: bold;
                color: #fff;
            }
            .stat-card .subtext {
                font-size: 12px;
                color: #aaa;
                margin-top: 5px;
            }
            .logs-section {
                background: rgba(0,0,0,0.3);
                border: 1px solid rgba(76,175,80,0.2);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
            }
            .logs-section h2 {
                color: #4CAF50;
                margin-bottom: 15px;
                font-size: 18px;
            }
            .log-item {
                background: rgba(0,0,0,0.2);
                border-right: 3px solid;
                padding: 12px;
                margin-bottom: 10px;
                border-radius: 4px;
                font-size: 12px;
                font-family: 'Courier New', monospace;
            }
            .log-item.success {
                border-color: #4CAF50;
            }
            .log-item.error {
                border-color: #f44336;
            }
            .log-item.info {
                border-color: #2196F3;
            }
            .log-time {
                color: #4CAF50;
                font-weight: bold;
            }
            .log-video {
                color: #2196F3;
            }
            .log-message {
                color: #aaa;
            }
            .status-badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: bold;
            }
            .status-online {
                background: #4CAF50;
                color: white;
            }
            .status-success {
                background: rgba(76,175,80,0.2);
                color: #4CAF50;
            }
            .status-error {
                background: rgba(244,67,54,0.2);
                color: #f44336;
            }
            .refresh-info {
                text-align: center;
                color: #888;
                font-size: 12px;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>⚡ Coursatk Proxy Server</h1>
                <p>لوحة تحكم ومراقبة التحميلات</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>🖥️ حالة السيرفر</h3>
                    <div class="value"><span class="status-badge status-online">🟢 Online</span></div>
                    <div class="subtext">السيرفر يعمل بكفاءة</div>
                </div>
                
                <div class="stat-card">
                    <h3>⏱️ وقت التشغيل</h3>
                    <div class="value">${hours}h ${minutes}m</div>
                    <div class="subtext">${seconds}s</div>
                </div>
                
                <div class="stat-card">
                    <h3>📥 إجمالي التحميلات</h3>
                    <div class="value">${downloadStats.totalDownloads}</div>
                    <div class="subtext">تحميلة حتى الآن</div>
                </div>
                
                <div class="stat-card">
                    <h3>🔄 التحميلات النشطة</h3>
                    <div class="value">${downloadStats.activeDownloads}</div>
                    <div class="subtext">تحميلة جارية</div>
                </div>
                
                <div class="stat-card">
                    <h3>💾 إجمالي البيانات</h3>
                    <div class="value">${(downloadStats.totalDataProcessed / 1024 / 1024).toFixed(2)}</div>
                    <div class="subtext">MB</div>
                </div>
                
                <div class="stat-card">
                    <h3>📋 السجلات</h3>
                    <div class="value">${downloadStats.logs.length}</div>
                    <div class="subtext">سجل التحميلات</div>
                </div>
            </div>
            
            <div class="logs-section">
                <h2>📝 آخر التحميلات</h2>
                ${downloadStats.logs.length === 0 
                    ? '<p style="color: #888; text-align: center;">لا توجد تحميلات حتى الآن</p>'
                    : downloadStats.logs.map(log => {
                        let statusClass = 'info';
                        if (log.status === 'success') statusClass = 'success';
                        if (log.status === 'error') statusClass = 'error';
                        const size = log.dataSize ? ` <span style="color: #4CAF50;">(${(log.dataSize / 1024 / 1024).toFixed(2)} MB)</span>` : '';
                        const time = new Date(log.timestamp).toLocaleTimeString('ar-EG');
                        return `<div class="log-item ${statusClass}"><span class="log-time">[${time}]</span><span class="log-video">الفيديو #${log.videoId}</span> - <span class="log-message">${log.message}</span>${size}</div>`;
                    }).join('')
                }
            </div>
            
            <div class="refresh-info">
                🔄 اضغط F5 لتحديث الصفحة | آخر تحديث: ${new Date().toLocaleTimeString('ar-EG')}
            </div>
        </div>
    </body>
    </html>
    `;
    res.send(html);
});

// ============================================
// Route: Health Check
// ============================================

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        server: 'Coursatk Proxy Server v1.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        downloads: {
            total: downloadStats.totalDownloads,
            active: downloadStats.activeDownloads,
            dataProcessed: downloadStats.totalDataProcessed
        }
    });
});

// ============================================
// Route: تحميل وفك تشفير الفيديو
// ============================================

app.post('/api/download', async (req, res) => {
    const startTime = Date.now();
    
    try {
        const {
            videoId,
            playbackToken,
            segments,
            encryptionKey,
            iv
        } = req.body;

        // التحقق من البيانات المرسلة
        if (!segments || !Array.isArray(segments) || segments.length === 0) {
            addLog(videoId, 'error', 'segments مطلوب ويجب أن يكون array');
            return res.status(400).json({
                error: 'segments مطلوب ويجب أن يكون array',
                received: typeof segments
            });
        }

        if (!encryptionKey || !iv) {
            addLog(videoId, 'error', 'encryptionKey و iv مطلوب');
            return res.status(400).json({
                error: 'encryptionKey و iv مطلوب'
            });
        }

        // زيادة عدد التحميلات النشطة
        downloadStats.activeDownloads++;
        downloadStats.totalDownloads++;
        addLog(videoId, 'info', `بدء التحميل - ${segments.length} مقطع`);

        console.log(`\n${'='.repeat(50)}`);
        console.log(`🎬 [${new Date().toISOString()}] بدء فك تشفير الفيديو #${videoId}`);
        console.log(`📊 عدد القطع: ${segments.length}`);
        console.log(`${'='.repeat(50)}`);

        // تحويل البيانات
        const keyBuffer = bufferFromData(encryptionKey);
        const ivBuffer = bufferFromData(iv);

        if (keyBuffer.length !== 16) {
            return res.status(400).json({
                error: `مفتاح التشفير يجب أن يكون 16 بايت، حصلنا على: ${keyBuffer.length}`
            });
        }

        if (ivBuffer.length !== 16) {
            return res.status(400).json({
                error: `IV يجب أن يكون 16 بايت، حصلنا على: ${ivBuffer.length}`
            });
        }

        // إرسال headers
        res.setHeader('Content-Type', 'video/mp4');
        res.setHeader('Content-Disposition', `attachment; filename="video_${videoId}.mp4"`);
        res.setHeader('Transfer-Encoding', 'chunked');
        res.setHeader('Cache-Control', 'no-cache');

        let totalProcessed = 0;
        let segmentIndex = 0;
        let failedSegments = 0;

        // معالجة القطع بـ streaming
        for (const segmentUrl of segments) {
            segmentIndex++;

            try {
                process.stdout.write(`\r📥 [${segmentIndex}/${segments.length}] تحميل...`);

                const encryptedData = await downloadSegment(segmentUrl, playbackToken);

                const decryptedData = decryptAES128CBC(encryptedData, keyBuffer, ivBuffer);

                totalProcessed += decryptedData.length;

                // إرسال القطعة
                res.write(decryptedData, (err) => {
                    if (err) {
                        console.error(`\n❌ خطأ في الإرسال:`, err.message);
                    }
                });

                // دع الـ CPU تتنفس كل 5 قطع
                if (segmentIndex % 5 === 0) {
                    await new Promise(r => setTimeout(r, 50));
                }

                process.stdout.write(`\r✅ [${segmentIndex}/${segments.length}] (${Math.round(totalProcessed / 1024 / 1024)} MB)`);

            } catch (error) {
                failedSegments++;
                console.error(`\n⚠️ خطأ في القطعة #${segmentIndex}:`, error.message);
                continue;
            }
        }

        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        const sizeInMB = Math.round(totalProcessed / 1024 / 1024);
        
        // تحديث الإحصائيات
        downloadStats.totalDataProcessed += totalProcessed;
        downloadStats.activeDownloads--;
        
        addLog(videoId, 'success', `✅ انتهى (${sizeInMB} MB في ${duration}s)`);
        
        console.log(`\n\n${'='.repeat(50)}`);
        console.log(`✅ انتهى الفك التشفير`);
        console.log(`📊 الحجم الكلي: ${sizeInMB} MB`);
        console.log(`⏱️ الوقت: ${duration} ثانية`);
        console.log(`⚠️ القطع الفاشلة: ${failedSegments}/${segments.length}`);
        console.log(`${'='.repeat(50)}\n`);

        res.end();

    } catch (error) {
        downloadStats.activeDownloads--;
        addLog(videoId, 'error', `❌ ${error.message}`);
        
        console.error('\n❌ خطأ عام:', error.message);
        if (!res.headersSent) {
            res.status(500).json({
                error: error.message || 'فشل في معالجة الفيديو'
            });
        } else {
            res.end();
        }
    }
});

// ============================================
// Route: معلومات عن الفيديو (للاختبار)
// ============================================

app.post('/api/info', (req, res) => {
    const { videoId, segments, encryptionKey, iv } = req.body;

    try {
        const keyBuffer = bufferFromData(encryptionKey);
        const ivBuffer = bufferFromData(iv);

        res.json({
            videoId,
            segmentCount: segments ? segments.length : 0,
            keySize: keyBuffer.length,
            ivSize: ivBuffer.length,
            firstSegment: segments ? segments[0] : null,
            status: '✅ البيانات صحيحة'
        });
    } catch (error) {
        res.status(400).json({
            error: error.message
        });
    }
});

// ============================================
// Error Handling
// ============================================

app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err);
    res.status(500).json({
        error: 'حدث خطأ في السيرفر',
        message: err.message
    });
});

// ============================================
// 404 Handler
// ============================================

app.use((req, res) => {
    res.status(404).json({
        error: 'المسار غير موجود',
        message: 'اذهب لـ /dashboard لمراقبة التحميلات',
        availableEndpoints: [
            'GET /dashboard - لوحة التحكم والمراقبة',
            'GET /health - حالة السيرفر',
            'POST /api/download - تحميل الفيديو',
            'POST /api/info - معلومات الفيديو'
        ]
    });
});

// ============================================
// البدء
// ============================================

const server = app.listen(PORT, () => {
    console.log('\n' + '═'.repeat(60));
    console.log('✅ Coursatk Proxy Server v1.0 - شغّال بكفاءة عالية');
    console.log('═'.repeat(60));
    console.log(`🚀 الـ URL الأساسي: http://localhost:${PORT}`);
    console.log(`📊 📊 لوحة التحكم: http://localhost:${PORT}/dashboard`);
    console.log(`💚 Health Check: http://localhost:${PORT}/health`);
    console.log(`\n📝 المسارات المتاحة:`);
    console.log(`   • GET /dashboard - لوحة التحكم والمراقبة`);
    console.log(`   • GET /health - حالة السيرفر والإحصائيات`);
    console.log(`   • POST /api/download - تحميل وفك تشفير الفيديو`);
    console.log(`   • POST /api/info - معلومات الفيديو`);
    console.log('═'.repeat(60) + '\n');
});

// Graceful Shutdown
process.on('SIGTERM', () => {
    console.log('\n⛔ إيقاف السيرفر...');
    server.close(() => {
        console.log('✅ تم إيقاف السيرفر بنجاح');
        process.exit(0);
    });
});
