const express = require("express");
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 3000;

// ===============================
// إعدادات الـ CDN المطلوبة
// ===============================
const DEFAULT_ORIGIN = "https://player.mediadelivery.net";

const DEFAULT_HEADERS = {
    "User-Agent":
        "Mozilla/5.0 (Linux; Android 15; CPH2591 Build/AP3A.240617.008) " +
        "AppleWebKit/537.36 (KHTML, like Gecko) Abck/4.0 " +
        "Chrome/150.0.7871.181 Mobile Safari/537.36",

    "Accept":
        "application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8," +
        "application/signed-exchange;v=b3;q=0.9",

    "Accept-Encoding": "identity",

    "Origin": DEFAULT_ORIGIN
};

// ======================================
// تنظيف وفك الروابط
// ======================================
function getTargetUrl(req) {
    const value = req.query.url;

    if (!value) {
        throw new Error("Missing url");
    }

    let decoded = decodeURIComponent(value);

    // منع البروتوكولات الغريبة
    const parsed = new URL(decoded);

    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only HTTP/HTTPS URLs are allowed");
    }

    return parsed;
}

// ======================================
// Headers للطلب الأصلي
// ======================================
function buildHeaders(targetUrl, isPlaylist = false) {
    const headers = {
        ...DEFAULT_HEADERS,
        Host: targetUrl.host,
        Referer: isPlaylist
            ? targetUrl.toString()
            : targetUrl.origin + "/"
    };

    // مهم لبعض الـ CDNs
    headers["Cookie"] = "googtrans=/auto/ar";

    return headers;
}

// ======================================
// تحويل رابط داخل M3U8 إلى Proxy URL
// ======================================
function makeProxyUrl(baseUrl, value) {
    value = value.trim();

    if (!value || value.startsWith("#")) {
        return value;
    }

    try {
        const absolute = new URL(value, baseUrl);

        return `/proxy?url=${encodeURIComponent(absolute.toString())}`;
    } catch {
        return value;
    }
}

// ======================================
// تعديل M3U8
// ======================================
function rewriteM3U8(content, baseUrl) {
    return content
        .split(/\r?\n/)
        .map(line => {
            const trimmed = line.trim();

            // روابط segments / playlists
            if (
                trimmed &&
                !trimmed.startsWith("#")
            ) {
                return makeProxyUrl(baseUrl, trimmed);
            }

            // بعض الـ M3U8 تستخدم URI="..."
            if (trimmed.startsWith("#")) {
                return trimmed.replace(
                    /URI="([^"]+)"/g,
                    (match, uri) => {
                        const proxied = makeProxyUrl(baseUrl, uri);
                        return `URI="${proxied}"`;
                    }
                );
            }

            return line;
        })
        .join("\n");
}

// ======================================
// Proxy الرئيسي
// ======================================
app.get("/proxy", async (req, res) => {
    try {
        const targetUrl = getTargetUrl(req);

        console.log("→", targetUrl.toString());

        const response = await fetch(
            targetUrl.toString(),
            {
                method: "GET",
                headers: buildHeaders(
                    targetUrl,
                    targetUrl.pathname.endsWith(".m3u8")
                ),
                redirect: "follow"
            }
        );

        console.log(
            "←",
            response.status,
            targetUrl.pathname
        );

        if (!response.ok) {
            const text = await response.text();

            return res.status(response.status).send(
                `Upstream error ${response.status}\n${text.slice(0, 500)}`
            );
        }

        const contentType =
            response.headers.get("content-type") || "";

        const isM3U8 =
            targetUrl.pathname.endsWith(".m3u8") ||
            contentType.includes("mpegurl") ||
            contentType.includes("m3u8");

        // ==================================
        // Playlist
        // ==================================
        if (isM3U8) {
            const text = await response.text();

            const rewritten = rewriteM3U8(
                text,
                targetUrl
            );

            res.status(200);
            res.setHeader(
                "Content-Type",
                "application/vnd.apple.mpegurl"
            );

            res.setHeader(
                "Cache-Control",
                "no-cache"
            );

            return res.send(rewritten);
        }

        // ==================================
        // Video segments / ملفات أخرى
        // ==================================

        res.status(response.status);

        const type = response.headers.get("content-type");

        if (type) {
            res.setHeader("Content-Type", type);
        }

        const length = response.headers.get("content-length");

        if (length) {
            res.setHeader("Content-Length", length);
        }

        res.setHeader(
            "Cache-Control",
            "public, max-age=60"
        );

        // streaming بدون تحميل الملف كله في RAM
        response.body.pipe(res);

    } catch (err) {
        console.error("Proxy error:", err);

        if (!res.headersSent) {
            res.status(500).json({
                error: "Proxy failed",
                message: err.message
            });
        }
    }
});

// ======================================
// Health check
// ======================================
app.get("/", (req, res) => {
    res.json({
        status: "online",
        service: "M3U8 Video Proxy",
        version: "1.0.0"
    });
});

// ======================================
// تشغيل السيرفر
// ======================================
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════╗
║       M3U8 VIDEO PROXY ONLINE       ║
╠══════════════════════════════════════╣
║ Port: ${PORT}
║ Status: ONLINE
╚══════════════════════════════════════╝
`);
});
