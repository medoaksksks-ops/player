/**
 * 🎬 Coursatk Video Decryption Server v2.0
 * مع لوحة تحكم ويب كاملة
 * 
 * npm install
 * node server.js
 * http://localhost:3000
 */

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// =========================================================
// الإعدادات
// =========================================================
const PORT = process.env.PORT || 3000;
const DOWNLOADS_DIR = path.join(__dirname, 'downloads');
const TEMP_DIR = path.join(__dirname, 'temp');
const MAX_CONCURRENT = 5;
const CHUNK_TIMEOUT = 10000;

// إنشاء المجلدات
if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// إعداد رفع الملفات
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// =========================================================
// نظام إدارة المعالجات
// =========================================================
const processingJobs = new Map();

class VideoProcessor {
    constructor(jobId, data) {
        this.jobId = jobId;
        this.videoId = data.videoId;
        this.segments = data.segments || [];
        this.token = data.token;
        this.wrappedKey = data.wrappedKey.data;
        this.iv = data.iv.data;
        
        this.progress = 0;
        this.status = 'initializing';
        this.stage = 'تجهيز';
        this.downloaded = 0;
        this.total = this.segments.length;
        this.error = null;
        this.downloadedSegments = [];
        this.startTime = Date.now();
        this.fileName = null;
    }

    log(msg) {
        const timestamp = new Date().toLocaleTimeString('ar-EG');
        console.log(`[${this.jobId}] [${timestamp}] ${msg}`);
    }

    setProgress(percent, status, stage) {
        this.progress = Math.min(percent, 100);
        this.status = status;
        if (stage) this.stage = stage;
        this.log(`📊 ${stage || this.stage} - ${this.progress}%`);
    }

    decryptSegment(encryptedData, key, iv) {
        try {
            const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
            let decrypted = decipher.update(encryptedData);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return decrypted;
        } catch (e) {
            this.log(`❌ خطأ في فك التشفير: ${e.message}`);
            throw e;
        }
    }

    async downloadSegment(url, retries = 2) {
        for (let i = 0; i < retries; i++) {
            try {
                const response = await axios.get(url, {
                    headers: { 'Authorization': `Bearer ${this.token}` },
                    responseType: 'arraybuffer',
                    timeout: CHUNK_TIMEOUT
                });
                return Buffer.from(response.data);
            } catch (e) {
                if (i === retries - 1) throw e;
                this.log(`⏳ إعادة محاولة ${i + 2}/${retries}...`);
                await new Promise(r => setTimeout(r, 500 * (i + 1)));
            }
        }
    }

    async downloadSegmentsParallel() {
        this.log(`📥 تحميل ${this.total} مقطع...`);
        this.setProgress(5, 'downloading', 'تحميل المقاطع');
        
        for (let i = 0; i < this.total; i += MAX_CONCURRENT) {
            const batch = [];

            for (let j = 0; j < MAX_CONCURRENT && i + j < this.total; j++) {
                const idx = i + j;
                
                batch.push(
                    this.downloadSegment(this.segments[idx])
                        .then(data => {
                            this.downloadedSegments[idx] = data;
                            this.downloaded++;
                            const percent = 5 + Math.round((this.downloaded / this.total) * 75);
                            this.setProgress(percent, 'downloading', 'تحميل المقاطع');
                        })
                        .catch(e => {
                            this.log(`❌ فشل المقطع ${idx}`);
                            throw e;
                        })
                );
            }

            await Promise.all(batch);
            
            if (i % (MAX_CONCURRENT * 2) === 0 && global.gc) {
                global.gc();
            }
        }

        this.log(`✅ تم تحميل جميع المقاطع!`);
    }

    async decryptSegments() {
        this.log(`🔐 فك التشفير...`);
        this.setProgress(82, 'decrypting', 'فك التشفير');
        
        const key = Buffer.from(this.wrappedKey);
        const iv = Buffer.from(this.iv);
        const decryptedSegments = [];
        
        for (let i = 0; i < this.total; i++) {
            try {
                const encrypted = this.downloadedSegments[i];
                const decrypted = this.decryptSegment(encrypted, key, iv);
                decryptedSegments.push(decrypted);
                
                const percent = 82 + Math.round((i + 1) / this.total * 10);
                this.setProgress(percent, 'decrypting', 'فك التشفير');

                this.downloadedSegments[i] = null;
            } catch (e) {
                throw e;
            }
        }

        this.log(`✅ تم فك التشفير!`);
        return decryptedSegments;
    }

    async mergeSegments(decryptedSegments) {
        this.log(`🔄 دمج المقاطع...`);
        this.setProgress(93, 'merging', 'دمج الملفات');
        
        this.fileName = `video_${this.videoId}_${Date.now()}.ts`;
        const outputPath = path.join(DOWNLOADS_DIR, this.fileName);

        return new Promise((resolve, reject) => {
            const writeStream = fs.createWriteStream(outputPath);
            let index = 0;

            const writeNext = () => {
                if (index >= decryptedSegments.length) {
                    writeStream.end();
                    resolve(outputPath);
                    return;
                }

                const segment = decryptedSegments[index];
                if (segment && segment.length > 0) {
                    writeStream.write(segment);
                }
                
                index++;
                const percent = 93 + Math.round((index / decryptedSegments.length) * 7);
                this.setProgress(percent, 'merging', 'دمج الملفات');

                writeNext();
            };

            writeStream.on('error', (e) => reject(e));
            writeNext();
        });
    }

    async process() {
        try {
            await this.downloadSegmentsParallel();
            const decryptedSegments = await this.decryptSegments();
            await this.mergeSegments(decryptedSegments);

            this.setProgress(100, 'completed', 'اكتمل!');
            this.status = 'completed';
            
            const fileSize = fs.statSync(path.join(DOWNLOADS_DIR, this.fileName)).size;
            this.log(`✅ النجاح! ${this.fileName} (${this.formatBytes(fileSize)})`);
            
            return {
                success: true,
                fileName: this.fileName,
                fileSize,
                downloadUrl: `/download/${this.fileName}`
            };

        } catch (error) {
            this.status = 'failed';
            this.error = error.message;
            this.log(`❌ فشل: ${error.message}`);
            throw error;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
    }

    getElapsedTime() {
        const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
        const hours = Math.floor(elapsed / 3600);
        const minutes = Math.floor((elapsed % 3600) / 60);
        const seconds = elapsed % 60;

        if (hours > 0) return `${hours}س ${minutes}د`;
        if (minutes > 0) return `${minutes}د ${seconds}ث`;
        return `${seconds}ثانية`;
    }
}

// =========================================================
// لوحة التحكم (HTML)
// =========================================================
const dashboardHTML = `
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎬 Coursatk Video Downloader</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f1e 0%, #1a1a2e 100%);
            color: #fff;
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #FF9800, #FFB74D);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            color: #aaa;
            font-size: 14px;
        }

        .card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }

        .upload-section h2 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #FFB74D;
        }

        .upload-area {
            border: 2px dashed #FF9800;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: rgba(255, 152, 0, 0.05);
        }

        .upload-area:hover {
            background: rgba(255, 152, 0, 0.1);
            border-color: #FFB74D;
        }

        .upload-area.dragover {
            background: rgba(255, 152, 0, 0.2);
            border-color: #FFB74D;
        }

        .upload-area p {
            font-size: 14px;
            color: #aaa;
            margin: 10px 0;
        }

        .upload-area strong {
            font-size: 16px;
            color: #FFB74D;
            display: block;
            margin-bottom: 10px;
        }

        #jsonInput {
            display: none;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            transition: all 0.3s;
            margin-top: 10px;
        }

        .btn-primary {
            background: linear-gradient(135deg, #FF9800, #F57C00);
            color: white;
            width: 100%;
        }

        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(255, 152, 0, 0.4);
        }

        .btn-primary:disabled {
            background: #666;
            cursor: not-allowed;
        }

        .btn-secondary {
            background: rgba(76, 175, 80, 0.2);
            color: #4CAF50;
            border: 1px solid #4CAF50;
        }

        .btn-secondary:hover {
            background: rgba(76, 175, 80, 0.3);
        }

        .btn-danger {
            background: rgba(244, 67, 54, 0.2);
            color: #f44336;
            border: 1px solid #f44336;
            font-size: 12px;
            padding: 8px 16px;
        }

        .job-section {
            margin-top: 30px;
        }

        .job-section h2 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #FFB74D;
        }

        .job-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }

        .job-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .job-title {
            font-weight: bold;
            color: #FFB74D;
        }

        .job-status {
            font-size: 12px;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
        }

        .status-downloading {
            background: rgba(33, 150, 243, 0.2);
            color: #2196F3;
        }

        .status-decrypting {
            background: rgba(156, 39, 176, 0.2);
            color: #9C27B0;
        }

        .status-merging {
            background: rgba(255, 193, 7, 0.2);
            color: #FFC107;
        }

        .status-completed {
            background: rgba(76, 175, 80, 0.2);
            color: #4CAF50;
        }

        .status-failed {
            background: rgba(244, 67, 54, 0.2);
            color: #f44336;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 8px;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #FF9800, #FFB74D);
            width: 0%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            color: #fff;
        }

        .job-info {
            font-size: 12px;
            color: #aaa;
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 12px;
            margin-top: 8px;
        }

        .job-info-item strong {
            color: #FFB74D;
            display: block;
            font-size: 13px;
        }

        .download-link {
            background: rgba(76, 175, 80, 0.1);
            border-left: 3px solid #4CAF50;
            padding: 12px;
            border-radius: 4px;
            margin-top: 8px;
        }

        .download-link a {
            color: #4CAF50;
            text-decoration: none;
            word-break: break-all;
            font-size: 12px;
        }

        .download-link a:hover {
            text-decoration: underline;
        }

        .error-message {
            background: rgba(244, 67, 54, 0.1);
            border-left: 3px solid #f44336;
            padding: 12px;
            border-radius: 4px;
            margin-top: 8px;
            color: #ff6f6f;
            font-size: 12px;
        }

        .files-section h2 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #FFB74D;
        }

        .file-item {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .file-name {
            flex: 1;
            font-size: 13px;
            color: #aaa;
            word-break: break-all;
        }

        .file-size {
            font-size: 12px;
            color: #888;
            margin: 0 16px;
            min-width: 80px;
            text-align: right;
        }

        .empty-message {
            text-align: center;
            color: #888;
            padding: 20px;
            font-size: 14px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loading {
            display: inline-block;
            animation: spin 1s linear infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- الرأس -->
        <div class="header">
            <h1>🎬 Coursatk Video Downloader</h1>
            <p>السيرفر يقوم بالتحميل وفك التشفير - موبايلك آمان 100%</p>
        </div>

        <!-- قسم الرفع -->
        <div class="card upload-section">
            <h2>📤 ارفع ملف البيانات</h2>
            
            <div class="upload-area" id="uploadArea">
                <strong>📁 اسحب ملف JSON هنا</strong>
                <p>أو اضغط للاختيار</p>
                <p style="font-size: 12px; color: #666;">الملف يجب أن يحتوي على بيانات الفيديو الكاملة</p>
            </div>

            <input type="file" id="jsonInput" accept=".json" />
            
            <button class="btn btn-primary" id="processBtn" disabled>
                🚀 ابدأ المعالجة
            </button>
        </div>

        <!-- قسم المعالجات الجارية -->
        <div class="job-section">
            <h2>📊 المعالجات الجارية</h2>
            <div id="jobsList">
                <div class="empty-message">لا توجد معالجات حالياً</div>
            </div>
        </div>

        <!-- قسم الملفات -->
        <div class="card files-section">
            <h2>📥 الملفات المحمّلة</h2>
            <div id="filesList">
                <div class="empty-message">لا توجد ملفات</div>
            </div>
        </div>
    </div>

    <script>
        let selectedFile = null;
        const uploadArea = document.getElementById('uploadArea');
        const jsonInput = document.getElementById('jsonInput');
        const processBtn = document.getElementById('processBtn');
        const jobsList = document.getElementById('jobsList');
        const filesList = document.getElementById('filesList');

        // معالجة الرفع بالسحب والإفلات
        uploadArea.addEventListener('click', () => jsonInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        });

        jsonInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });

        function handleFile(file) {
            if (!file.name.endsWith('.json')) {
                alert('❌ الرجاء اختيار ملف JSON');
                return;
            }

            selectedFile = file;
            uploadArea.innerHTML = \`
                <strong>✅ تم اختيار الملف</strong>
                <p style="font-size: 12px;">\${file.name}</p>
                <p style="font-size: 12px; color: #888;">\${(file.size / 1024).toFixed(2)} KB</p>
            \`;
            processBtn.disabled = false;
        }

        processBtn.addEventListener('click', async () => {
            if (!selectedFile) {
                alert('❌ الرجاء اختيار ملف');
                return;
            }

            processBtn.disabled = true;
            processBtn.textContent = '⏳ جاري الرفع...';

            try {
                const formData = new FormData();
                formData.append('jsonFile', selectedFile);

                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (!result.success) {
                    throw new Error(result.error || 'خطأ في المعالجة');
                }

                uploadArea.innerHTML = \`
                    <strong>✅ تم الرفع والمعالجة</strong>
                    <p>Job ID: \${result.jobId}</p>
                \`;

                // شاهد التقدم
                monitorJob(result.jobId);

                // حمّل قائمة الملفات
                refreshFiles();

            } catch (error) {
                alert('❌ خطأ: ' + error.message);
            } finally {
                processBtn.disabled = false;
                processBtn.textContent = '🚀 ابدأ المعالجة';
            }
        });

        async function monitorJob(jobId) {
            const interval = setInterval(async () => {
                try {
                    const response = await fetch(\`/api/status/\${jobId}\`);
                    const status = await response.json();

                    if (!status.success) {
                        clearInterval(interval);
                        return;
                    }

                    updateJobUI(status);

                    if (status.status === 'completed' || status.status === 'failed') {
                        clearInterval(interval);
                        refreshFiles();
                    }
                } catch (e) {
                    console.error('خطأ في المراقبة:', e);
                }
            }, 500);
        }

        function updateJobUI(status) {
            let jobHTML = document.getElementById(\`job-\${status.jobId}\`);
            
            if (!jobHTML) {
                jobHTML = document.createElement('div');
                jobHTML.id = \`job-\${status.jobId}\`;
                jobHTML.className = 'job-card';
                jobsList.innerHTML = '';
                jobsList.appendChild(jobHTML);
            }

            let statusClass = 'status-' + status.status;
            let statusText = {
                'initializing': '🔧 تجهيز',
                'downloading': '📥 تحميل',
                'decrypting': '🔐 فك تشفير',
                'merging': '🔄 دمج',
                'completed': '✅ اكتمل',
                'failed': '❌ فشل'
            }[status.status] || status.status;

            let elapsedTime = Math.floor((Date.now() - Date.now()) / 1000);
            let timeStr = \`\${Math.floor(elapsedTime / 60)}د \${elapsedTime % 60}ث\`;

            let html = \`
                <div class="job-header">
                    <div class="job-title">الفيديو #\${status.videoId}</div>
                    <div class="job-status \${statusClass}">
                        \${statusText} \${status.progress}%
                    </div>
                </div>

                <div class="progress-bar">
                    <div class="progress-fill" style="width: \${status.progress}%">
                        \${status.progress}%
                    </div>
                </div>

                <div class="job-info">
                    <div>
                        <strong>\${status.stage || 'جاهز'}</strong>
                        <span>\${status.message}</span>
                    </div>
                    <div>
                        <strong>\${status.downloaded}/\${status.total}</strong>
                        <span>المقاطع المحملة</span>
                    </div>
                </div>
            \`;

            if (status.status === 'completed' && status.downloadUrl) {
                html += \`
                    <div class="download-link">
                        <strong>✅ اكتمل التحميل!</strong>
                        <a href="\${status.downloadUrl}" download>📥 حمّل الملف: \${status.fileName}</a>
                    </div>
                \`;
            }

            if (status.status === 'failed' && status.error) {
                html += \`
                    <div class="error-message">
                        <strong>❌ خطأ:</strong> \${status.error}
                    </div>
                \`;
            }

            jobHTML.innerHTML = html;
        }

        async function refreshFiles() {
            try {
                const response = await fetch('/api/files');
                const result = await response.json();

                if (!result.success || result.files.length === 0) {
                    filesList.innerHTML = '<div class="empty-message">لا توجد ملفات</div>';
                    return;
                }

                let html = '';
                result.files.forEach(file => {
                    html += \`
                        <div class="file-item">
                            <div class="file-name">
                                <strong>🎬 \${file.filename}</strong>
                                <br>
                                <span style="font-size: 11px; color: #666;">\${file.created}</span>
                            </div>
                            <div class="file-size">\${file.sizeFormatted}</div>
                            <a href="\${file.url}" download class="btn btn-secondary">📥</a>
                            <button class="btn btn-danger" onclick="deleteFile('\${file.filename}')">🗑️</button>
                        </div>
                    \`;
                });

                filesList.innerHTML = html;
            } catch (e) {
                console.error('خطأ في تحميل الملفات:', e);
            }
        }

        async function deleteFile(filename) {
            if (!confirm('هل أنت متأكد من حذف الملف؟')) return;

            try {
                const response = await fetch(\`/api/files/\${filename}\`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    refreshFiles();
                } else {
                    alert('❌ فشل الحذف');
                }
            } catch (e) {
                alert('❌ خطأ: ' + e.message);
            }
        }

        // حدّث الملفات عند التحميل
        refreshFiles();

        // حدّث الملفات كل 10 ثواني
        setInterval(refreshFiles, 10000);
    </script>
</body>
</html>
`;

// =========================================================
// المسارات
// =========================================================

// الصفحة الرئيسية
app.get('/', (req, res) => {
    res.send(dashboardHTML);
});

// رفع الملف ومعالجته
app.post('/api/upload', upload.single('jsonFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'لم يتم رفع ملف' });
        }

        let data;
        try {
            data = JSON.parse(req.file.buffer.toString());
        } catch (e) {
            return res.status(400).json({ success: false, error: 'ملف JSON غير صحيح' });
        }

        if (!data.videoId || !data.segments || !data.token) {
            return res.status(400).json({ 
                success: false, 
                error: 'البيانات ناقصة - تأكد من وجود videoId, segments, token' 
            });
        }

        const jobId = uuidv4().substring(0, 8);
        const processor = new VideoProcessor(jobId, data);
        processingJobs.set(jobId, processor);

        console.log(`\n${'═'.repeat(60)}`);
        console.log(`🎬 معالجة جديدة - Job ID: ${jobId}`);
        console.log(`📊 الفيديو: #${data.videoId}`);
        console.log(`📥 المقاطع: ${data.segments.length}`);
        console.log(`${'═'.repeat(60)}\n`);

        // معالجة غير متزامنة
        processor.process()
            .then(result => {
                // Keep the job in memory so the browser can receive the
                // final "completed" status and download URL.
                processor.log(`✅ اكتملت المعالجة`);
            })
            .catch(error => {
                // Keep the failed job as well so the browser can display
                // the actual error instead of receiving a 404.
                processor.log(`❌ خطأ في المعالجة: ${error.message}`);
            });

        res.json({
            success: true,
            jobId,
            message: 'جاري المعالجة في الخلفية...'
        });

    } catch (error) {
        console.error('[POST /api/upload]', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// حالة المعالجة
app.get('/api/status/:jobId', (req, res) => {
    const { jobId } = req.params;
    const processor = processingJobs.get(jobId);

    if (!processor) {
        return res.status(404).json({
            success: false,
            error: 'معرّف المعالجة غير موجود'
        });
    }

    res.json({
        success: true,
        jobId,
        videoId: processor.videoId,
        status: processor.status,
        stage: processor.stage,
        progress: processor.progress,
        downloaded: processor.downloaded,
        total: processor.total,
        error: processor.error,
        message: processor.stage,
        fileName: processor.fileName,
        downloadUrl: processor.fileName ? `/download/${processor.fileName}` : null,
        elapsedTime: processor.getElapsedTime()
    });
});

// تحميل الملف
app.get('/download/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        const filepath = path.join(DOWNLOADS_DIR, filename);

        if (!filepath.startsWith(DOWNLOADS_DIR)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        if (!fs.existsSync(filepath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        const stat = fs.statSync(filepath);
        res.setHeader('Content-Type', 'video/mp2ts');
        res.setHeader('Content-Length', stat.size);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

        const stream = fs.createReadStream(filepath);
        stream.pipe(res);

        console.log(`📥 جاري تحميل: ${filename}`);

    } catch (error) {
        console.error('[GET /download]', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// قائمة الملفات
app.get('/api/files', (req, res) => {
    try {
        const files = fs.readdirSync(DOWNLOADS_DIR);
        const fileList = files.map(filename => {
            const filepath = path.join(DOWNLOADS_DIR, filename);
            const stat = fs.statSync(filepath);
            return {
                filename,
                size: stat.size,
                sizeFormatted: formatBytes(stat.size),
                created: stat.birthtime.toLocaleString('ar-EG'),
                url: `/download/${filename}`
            };
        });

        res.json({ success: true, files: fileList });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// حذف الملف
app.delete('/api/files/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        const filepath = path.join(DOWNLOADS_DIR, filename);

        if (!filepath.startsWith(DOWNLOADS_DIR)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        if (!fs.existsSync(filepath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        fs.unlinkSync(filepath);
        console.log(`🗑️ تم حذف الملف: ${filename}`);

        res.json({ success: true, message: 'تم حذف الملف بنجاح' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// =========================================================
// المساعدات
// =========================================================
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

// تنظيف دوري
setInterval(() => {
    try {
        const files = fs.readdirSync(DOWNLOADS_DIR);
        const now = Date.now();
        const maxAge = 7 * 24 * 60 * 60 * 1000;

        files.forEach(file => {
            const filepath = path.join(DOWNLOADS_DIR, file);
            const stat = fs.statSync(filepath);
            
            if (now - stat.birthtime > maxAge) {
                fs.unlinkSync(filepath);
                console.log(`🧹 حذف ملف قديم: ${file}`);
            }
        });
    } catch (e) {
        console.error('خطأ في التنظيف:', e);
    }
}, 24 * 60 * 60 * 1000);

// تنظيف المعالجات المنتهية بعد ساعة، مع إبقاءها متاحة للواجهة أثناء المعالجة
setInterval(() => {
    try {
        const now = Date.now();
        for (const [jobId, processor] of processingJobs.entries()) {
            const age = now - processor.startTime;
            const finished = processor.status === 'completed' || processor.status === 'failed';
            if (finished && age > 60 * 60 * 1000) {
                processingJobs.delete(jobId);
            }
        }
    } catch (e) {
        console.error('خطأ في تنظيف المعالجات:', e);
    }
}, 10 * 60 * 1000);

// بدء الخادم
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║  🎬 Coursatk Video Decryption Server v2.0                 ║
║  مع لوحة تحكم ويب كاملة                                   ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ║
║  ✅ الخادم يعمل على:                                      ║
║                                                            ║
║     🌐 http://localhost:${PORT}                           ║
║                                                            ║
║  افتح الرابط واستخدم اللوحة مباشرة!                     ║
║                                                            ║
║  الخطوات:                                                 ║
║  1. اذهب للرابط أعلاه                                    ║
║  2. اسحب ملف JSON أو اضغط لاختيار                        ║
║  3. اضغط "ابدأ المعالجة"                                ║
║  4. شاهد التقدم مباشرة                                   ║
║  5. حمّل الملف عند الانتهاء                              ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    `);
});

module.exports = app;