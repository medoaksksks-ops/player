const express = require("express");
const fetch = require("node-fetch");

const app = express();

const PORT = process.env.PORT || 3000;

// =====================================================
// CORS — مفتوح لأي مصدر
// =====================================================

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, HEAD, OPTIONS"
    );

    res.setHeader(
        "Access-Control-Allow-Headers",
        [
            "Origin",
            "X-Requested-With",
            "Content-Type",
            "Accept",
            "Range"
        ].join(", ")
    );

    res.setHeader(
        "Access-Control-Expose-Headers",
        [
            "Content-Length",
            "Content-Range",
            "Accept-Ranges",
            "Content-Type"
        ].join(", ")
    );

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});


// =====================================================
// Headers المطلوبة للـ CDN
// =====================================================

const UPSTREAM_ORIGIN =
    "https://player.mediadelivery.net";

const USER_AGENT =
    "Mozilla/5.0 (Linux; Android 15; CPH2591 Build/AP3A.240617.008) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Abck/4.0 " +
    "Chrome/150.0.7871.181 Mobile Safari/537.36";


// =====================================================
// الحصول على الرابط
// =====================================================

function getTargetUrl(req) {

    const rawUrl = req.query.url;

    if (!rawUrl) {
        throw new Error("Missing url parameter");
    }

    let decoded;

    try {
        decoded = decodeURIComponent(rawUrl);
    } catch {
        decoded = rawUrl;
    }

    const url = new URL(decoded);

    if (
        url.protocol !== "http:" &&
        url.protocol !== "https:"
    ) {
        throw new Error(
            "Only HTTP and HTTPS URLs are allowed"
        );
    }

    return url;
}


// =====================================================
// بناء Headers للطلب الخارجي
// =====================================================

function buildUpstreamHeaders(req, targetUrl) {

    const headers = {
        "User-Agent": USER_AGENT,

        "Accept":
            "application/xhtml+xml,application/xml;q=0.9," +
            "image/webp,image/apng,*/*;q=0.8," +
            "application/signed-exchange;v=b3;q=0.9",

        "Accept-Encoding": "identity",

        "Origin": UPSTREAM_ORIGIN,

        "Referer": UPSTREAM_ORIGIN + "/"
    };


    // Cookie الخاص بالطلب الأصلي
    headers["Cookie"] = "googtrans=/auto/ar";


    // -------------------------------------------------
    // تمرير Range لو موجود
    // مهم جداً للـ video segments
    // -------------------------------------------------

    if (req.headers.range) {
        headers["Range"] = req.headers.range;
    }


    return headers;
}


// =====================================================
// تحويل الروابط الموجودة داخل M3U8
// =====================================================

function proxyUrl(targetUrl) {

    return (
        "/proxy?url=" +
        encodeURIComponent(targetUrl.toString())
    );
}


// =====================================================
// تحويل M3U8
// =====================================================

function rewriteM3U8(content, baseUrl) {

    return content
        .split(/\r?\n/)
        .map(line => {

            const trimmed = line.trim();


            // -----------------------------------------
            // روابط segments / playlists
            // -----------------------------------------

            if (
                trimmed &&
                !trimmed.startsWith("#")
            ) {

                try {

                    const absoluteUrl =
                        new URL(
                            trimmed,
                            baseUrl
                        );

                    return proxyUrl(
                        absoluteUrl
                    );

                } catch {

                    return line;
                }
            }


            // -----------------------------------------
            // روابط URI داخل الـ tags
            // مثل:
            //
            // #EXT-X-KEY:URI="..."
            // #EXT-X-MAP:URI="..."
            // -----------------------------------------

            if (
                trimmed.startsWith("#") &&
                trimmed.includes('URI="')
            ) {

                return trimmed.replace(
                    /URI="([^"]+)"/g,
                    (match, uri) => {

                        try {

                            const absoluteUrl =
                                new URL(
                                    uri,
                                    baseUrl
                                );

                            return (
                                'URI="' +
                                proxyUrl(
                                    absoluteUrl
                                ) +
                                '"'
                            );

                        } catch {

                            return match;
                        }
                    }
                );
            }


            return line;
        })
        .join("\n");
}


// =====================================================
// معرفة هل الملف M3U8
// =====================================================

function isM3U8(targetUrl, contentType) {

    const path =
        targetUrl.pathname.toLowerCase();

    const type =
        (contentType || "").toLowerCase();

    return (
        path.endsWith(".m3u8") ||
        path.endsWith(".m3u") ||
        type.includes("mpegurl") ||
        type.includes("m3u8")
    );
}


// =====================================================
// Proxy
// =====================================================

app.all("/proxy", async (req, res) => {

    try {

        // السماح فقط بـ GET / HEAD
        if (
            req.method !== "GET" &&
            req.method !== "HEAD"
        ) {

            return res.status(405).json({
                error: "Method Not Allowed"
            });
        }


        // ---------------------------------------------
        // Target URL
        // ---------------------------------------------

        const targetUrl =
            getTargetUrl(req);


        console.log(
            "→",
            req.method,
            targetUrl.toString()
        );


        // ---------------------------------------------
        // Headers
        // ---------------------------------------------

        const headers =
            buildUpstreamHeaders(
                req,
                targetUrl
            );


        // ---------------------------------------------
        // Request
        // ---------------------------------------------

        const upstream =
            await fetch(
                targetUrl.toString(),
                {
                    method: req.method,
                    headers,
                    redirect: "follow"
                }
            );


        console.log(
            "←",
            upstream.status,
            targetUrl.pathname
        );


        // ---------------------------------------------
        // Upstream error
        // ---------------------------------------------

        if (!upstream.ok) {

            let message = "";

            if (req.method !== "HEAD") {

                try {
                    message =
                        await upstream.text();
                } catch {
                    message = "";
                }
            }


            return res
                .status(upstream.status)
                .send(
                    "Upstream error " +
                    upstream.status +
                    "\n" +
                    message.slice(0, 500)
                );
        }


        const contentType =
            upstream.headers.get(
                "content-type"
            ) || "";


        // =================================================
        // M3U8 PLAYLIST
        // =================================================

        if (
            isM3U8(
                targetUrl,
                contentType
            )
        ) {

            if (req.method === "HEAD") {

                res.status(200);

                res.setHeader(
                    "Content-Type",
                    "application/vnd.apple.mpegurl"
                );

                return res.end();
            }


            const playlist =
                await upstream.text();


            const rewritten =
                rewriteM3U8(
                    playlist,
                    targetUrl
                );


            res.status(200);


            res.setHeader(
                "Content-Type",
                "application/vnd.apple.mpegurl"
            );


            res.setHeader(
                "Cache-Control",
                "no-cache, no-store, must-revalidate"
            );


            res.setHeader(
                "Pragma",
                "no-cache"
            );


            res.setHeader(
                "Content-Length",
                Buffer.byteLength(
                    rewritten,
                    "utf8"
                )
            );


            return res.send(
                rewritten
            );
        }


        // =================================================
        // VIDEO SEGMENTS / FILES
        // =================================================

        res.status(
            upstream.status
        );


        // Content-Type

        if (contentType) {

            res.setHeader(
                "Content-Type",
                contentType
            );
        }


        // Content-Length

        const contentLength =
            upstream.headers.get(
                "content-length"
            );

        if (contentLength) {

            res.setHeader(
                "Content-Length",
                contentLength
            );
        }


        // Content-Range

        const contentRange =
            upstream.headers.get(
                "content-range"
            );

        if (contentRange) {

            res.setHeader(
                "Content-Range",
                contentRange
            );
        }


        // Accept-Ranges

        const acceptRanges =
            upstream.headers.get(
                "accept-ranges"
            );

        res.setHeader(
            "Accept-Ranges",
            acceptRanges || "bytes"
        );


        // Cache

        res.setHeader(
            "Cache-Control",
            "public, max-age=60"
        );


        // HEAD لا يحتاج body

        if (req.method === "HEAD") {

            return res.end();
        }


        // =================================================
        // Streaming
        // =================================================

        if (upstream.body) {

            upstream.body.pipe(res);

        } else {

            res.end();
        }

    } catch (error) {

        console.error(
            "Proxy error:",
            error
        );


        if (!res.headersSent) {

            return res
                .status(500)
                .json({
                    error: "Proxy failed",
                    message: error.message
                });
        }


        res.end();
    }
});


// =====================================================
// Health Check
// =====================================================

app.get("/", (req, res) => {

    res.json({
        status: "online",
        service: "M3U8 HLS Proxy",
        version: "2.0.0",
        cors: "enabled",
        range: true,
        streaming: true
    });
});


// =====================================================
// 404
// =====================================================

app.use((req, res) => {

    res.status(404).json({
        error: "Not Found"
    });
});


// =====================================================
// Start
// =====================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log("");
        console.log(
            "===================================="
        );
        console.log(
            "       M3U8 HLS PROXY ONLINE"
        );
        console.log(
            "===================================="
        );
        console.log(
            "Port:",
            PORT
        );
        console.log(
            "CORS: *"
        );
        console.log(
            "Range: enabled"
        );
        console.log(
            "Streaming: enabled"
        );
        console.log(
            "===================================="
        );
        console.log("");
    }
);
