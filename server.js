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
// Route: Health Check
// ============================================

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        server: 'Coursatk Proxy Server v1.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
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
            return res.status(400).json({
                error: 'segments مطلوب ويجب أن يكون array',
                received: typeof segments
            });
        }

        if (!encryptionKey || !iv) {
            return res.status(400).json({
                error: 'encryptionKey و iv مطلوب'
            });
        }

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
        console.log(`\n\n${'='.repeat(50)}`);
        console.log(`✅ انتهى الفك التشفير`);
        console.log(`📊 الحجم الكلي: ${Math.round(totalProcessed / 1024 / 1024)} MB`);
        console.log(`⏱️ الوقت: ${duration} ثانية`);
        console.log(`⚠️ القطع الفاشلة: ${failedSegments}/${segments.length}`);
        console.log(`${'='.repeat(50)}\n`);

        res.end();

    } catch (error) {
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
        availableEndpoints: [
            'GET /health',
            'POST /api/download',
            'POST /api/info'
        ]
    });
});

// ============================================
// البدء
// ============================================

const server = app.listen(PORT, () => {
    console.log('\n' + '═'.repeat(50));
    console.log('✅ Coursatk Proxy Server v1.0');
    console.log('═'.repeat(50));
    console.log(`🚀 الـ URL: http://localhost:${PORT}`);
    console.log(`📥 POST /api/download - تحميل وفك تشفير الفيديو`);
    console.log(`💚 GET /health - حالة السيرفر`);
    console.log(`📊 POST /api/info - معلومات الفيديو`);
    console.log('═'.repeat(50) + '\n');
});

// Graceful Shutdown
process.on('SIGTERM', () => {
    console.log('\n⛔ إيقاف السيرفر...');
    server.close(() => {
        console.log('✅ تم إيقاف السيرفر بنجاح');
        process.exit(0);
    });
});
                               
