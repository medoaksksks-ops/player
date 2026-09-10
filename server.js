/**
 * Facebook API Server
 * Version: 2.0.0
 *
 * الاستخدام:
 *   - يعتمد على Meta Graph API الرسمي.
 *   - FB_ACCESS_TOKEN و FB_PAGE_ID في .env
 *   - FB_COOKIE اختياري وموجود فقط للحفاظ على إعدادك الحالي،
 *     لكنه لا يُستخدم لتجاوز قيود Facebook أو استخراج روابط فيديو مخفية.
 */

require("dotenv").config();

const express = require("express");
const axios = require("axios");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const FB_ACCESS_TOKEN = process.env.FB_ACCESS_TOKEN || "";
const FB_PAGE_ID = process.env.FB_PAGE_ID || "";

const GRAPH_VERSION =
  process.env.FB_GRAPH_VERSION || "v23.0";

const GRAPH_BASE =
  `https://graph.facebook.com/${GRAPH_VERSION}`;

app.use(express.json({ limit: "1mb" }));

/* -------------------------------------------------------
   Helpers
------------------------------------------------------- */

function jsonError(res, status, code, message, extra = {}) {
  return res.status(status).json({
    ok: false,
    error: code,
    message,
    ...extra
  });
}

function graphConfigured() {
  return Boolean(FB_ACCESS_TOKEN);
}

function cleanText(value) {
  if (typeof value !== "string") return "";
  return value.trim();
}

function normalizePost(post) {
  return {
    id: post.id || null,
    message: cleanText(post.message),
    created_time: post.created_time || null,
    permalink_url: post.permalink_url || null,
    full_picture: post.full_picture || null,
    type: post.type || null,
    status_type: post.status_type || null
  };
}

/* -------------------------------------------------------
   Graph API client
------------------------------------------------------- */

const graph = axios.create({
  baseURL: GRAPH_BASE,
  timeout: 20000,
  headers: {
    Accept: "application/json",
    "User-Agent":
      "Facebook-API-Server/2.0"
  },
  validateStatus: () => true
});

async function graphGet(path, params = {}) {
  if (!FB_ACCESS_TOKEN) {
    const err = new Error(
      "FB_ACCESS_TOKEN is not configured"
    );

    err.code = "missing_access_token";

    throw err;
  }

  const response = await graph.get(path, {
    params: {
      access_token: FB_ACCESS_TOKEN,
      ...params
    }
  });

  return response;
}

function handleGraphResponse(res, response) {
  const body = response.data || {};

  if (response.status >= 200 && response.status < 300) {
    return null;
  }

  const graphError = body.error || {};

  let message =
    graphError.message ||
    "Facebook Graph API returned an error";

  if (response.status === 401) {
    message =
      "Access token is invalid, expired, or unauthorized.";
  } else if (response.status === 403) {
    message =
      "The token does not have permission to access this resource.";
  } else if (response.status === 429) {
    message =
      "Facebook Graph API rate limit reached.";
  }

  return jsonError(
    res,
    response.status || 502,
    "facebook_api_error",
    message,
    {
      facebook: {
        type: graphError.type || null,
        code: graphError.code || null,
        subcode: graphError.error_subcode || null,
        trace_id: graphError.fbtrace_id || null
      }
    }
  );
}

/* -------------------------------------------------------
   Health
------------------------------------------------------- */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "facebook-api-server",
    version: "2.0.0",
    graph_version: GRAPH_VERSION,
    configured: {
      access_token: Boolean(FB_ACCESS_TOKEN),
      page_id: Boolean(FB_PAGE_ID),
      legacy_cookie_present: Boolean(
        process.env.FB_COOKIE
      )
    },
    time: new Date().toISOString()
  });
});

/* -------------------------------------------------------
   Debug configuration
------------------------------------------------------- */

app.get("/api/config", (req, res) => {
  res.json({
    ok: true,
    graph_version: GRAPH_VERSION,
    access_token_configured:
      Boolean(FB_ACCESS_TOKEN),
    page_id_configured:
      Boolean(FB_PAGE_ID),

    /*
     * لا نعرض قيمة الكوكيز أو الـAccess Token.
     */
    cookie_configured:
      Boolean(process.env.FB_COOKIE)
  });
});

/* -------------------------------------------------------
   Page information
------------------------------------------------------- */

app.get("/api/page", async (req, res) => {
  if (!graphConfigured()) {
    return jsonError(
      res,
      500,
      "missing_access_token",
      "FB_ACCESS_TOKEN is missing from .env"
    );
  }

  const pageId =
    req.query.id ||
    FB_PAGE_ID;

  if (!pageId) {
    return jsonError(
      res,
      400,
      "missing_page_id",
      "Pass ?id=PAGE_ID or set FB_PAGE_ID in .env"
    );
  }

  try {
    const response = await graphGet(
      `/${encodeURIComponent(pageId)}`,
      {
        fields: [
          "id",
          "name",
          "username",
          "about",
          "category",
          "picture",
          "cover",
          "link"
        ].join(",")
      }
    );

    const handled =
      handleGraphResponse(res, response);

    if (handled) return handled;

    return res.json({
      ok: true,
      page: response.data
    });

  } catch (err) {
    return jsonError(
      res,
      502,
      "facebook_request_failed",
      err.message
    );
  }
});

/* -------------------------------------------------------
   Feed / Posts
------------------------------------------------------- */

app.get("/api/feed", async (req, res) => {
  if (!graphConfigured()) {
    return jsonError(
      res,
      500,
      "missing_access_token",
      "FB_ACCESS_TOKEN is missing from .env"
    );
  }

  const pageId =
    req.query.page_id ||
    FB_PAGE_ID;

  if (!pageId) {
    return jsonError(
      res,
      400,
      "missing_page_id",
      "Set FB_PAGE_ID in .env or pass ?page_id=PAGE_ID"
    );
  }

  const limit = Math.min(
    Math.max(
      Number(req.query.limit || 20),
      1
    ),
    100
  );

  try {
    const response = await graphGet(
      `/${encodeURIComponent(pageId)}/posts`,
      {
        fields: [
          "id",
          "message",
          "created_time",
          "permalink_url",
          "full_picture",
          "type",
          "status_type"
        ].join(","),
        limit
      }
    );

    const handled =
      handleGraphResponse(res, response);

    if (handled) return handled;

    const data =
      Array.isArray(response.data)
        ? response.data.map(normalizePost)
        : [];

    return res.json({
      ok: true,
      count: data.length,
      items: data,
      paging: response.paging || null
    });

  } catch (err) {
    return jsonError(
      res,
      502,
      "facebook_request_failed",
      err.message
    );
  }
});

/* -------------------------------------------------------
   Single post
------------------------------------------------------- */

app.get("/api/item", async (req, res) => {
  if (!graphConfigured()) {
    return jsonError(
      res,
      500,
      "missing_access_token",
      "FB_ACCESS_TOKEN is missing from .env"
    );
  }

  const id = cleanText(req.query.id);

  if (!id) {
    return jsonError(
      res,
      400,
      "missing_id",
      "Use /api/item?id=POST_ID"
    );
  }

  try {
    const response = await graphGet(
      `/${encodeURIComponent(id)}`,
      {
        fields: [
          "id",
          "message",
          "created_time",
          "permalink_url",
          "full_picture",
          "type",
          "status_type"
        ].join(",")
      }
    );

    const handled =
      handleGraphResponse(res, response);

    if (handled) return handled;

    return res.json({
      ok: true,
      item: normalizePost(response.data)
    });

  } catch (err) {
    return jsonError(
      res,
      502,
      "facebook_request_failed",
      err.message
    );
  }
});

/* -------------------------------------------------------
   Page videos
------------------------------------------------------- */

app.get("/api/page/videos", async (req, res) => {
  if (!graphConfigured()) {
    return jsonError(
      res,
      500,
      "missing_access_token",
      "FB_ACCESS_TOKEN is missing from .env"
    );
  }

  const pageId =
    req.query.page_id ||
    FB_PAGE_ID;

  if (!pageId) {
    return jsonError(
      res,
      400,
      "missing_page_id",
      "Set FB_PAGE_ID in .env"
    );
  }

  const limit = Math.min(
    Math.max(
      Number(req.query.limit || 20),
      1
    ),
    100
  );

  try {
    /*
     * نطلب المنشورات التي تحتوي على فيديو
     * من خلال الحقول/البيانات التي يسمح بها Graph API.
     */
    const response = await graphGet(
      `/${encodeURIComponent(pageId)}/posts`,
      {
        fields: [
          "id",
          "message",
          "created_time",
          "permalink_url",
          "full_picture",
          "type",
          "status_type"
        ].join(","),
        limit
      }
    );

    const handled =
      handleGraphResponse(res, response);

    if (handled) return handled;

    const posts =
      Array.isArray(response.data)
        ? response.data
        : [];

    const videos = posts
      .filter(post =>
        post.type === "video" ||
        post.status_type === "added_video"
      )
      .map(normalizePost);

    return res.json({
      ok: true,
      count: videos.length,
      items: videos,
      paging: response.paging || null
    });

  } catch (err) {
    return jsonError(
      res,
      502,
      "facebook_request_failed",
      err.message
    );
  }
});

/* -------------------------------------------------------
   Search-like endpoint
------------------------------------------------------- */

app.get("/api/search", async (req, res) => {
  if (!graphConfigured()) {
    return jsonError(
      res,
      500,
      "missing_access_token",
      "FB_ACCESS_TOKEN is missing from .env"
    );
  }

  const query =
    cleanText(req.query.q);

  if (!query) {
    return jsonError(
      res,
      400,
      "missing_query",
      "Use /api/search?q=QUERY"
    );
  }

  /*
   * لا نحاول تقليد بحث Facebook الداخلي.
   * هذا endpoint مخصص فقط لتوضيح أن البحث العام
   * يجب أن يتم عبر endpoint رسمي يدعم هذا النوع من البحث.
   */
  return res.status(400).json({
    ok: false,
    error: "unsupported_search",
    message:
      "General Facebook content search is not exposed here through an unofficial HTML scraper.",
    query
  });
});

/* -------------------------------------------------------
   Legacy raw endpoint
------------------------------------------------------- */

app.get("/api/raw", async (req, res) => {
  return res.status(410).json({
    ok: false,
    error: "legacy_endpoint_disabled",
    message:
      "The old mbasic HTML scraping endpoint has been disabled.",
    reason:
      "Facebook may return an Unsupported Browser page instead of the requested content."
  });
});

/* -------------------------------------------------------
   404 API handler
------------------------------------------------------- */

app.use("/api", (req, res) => {
  return jsonError(
    res,
    404,
    "endpoint_not_found",
    `Unknown API endpoint: ${req.method} ${req.path}`
  );
});

/* -------------------------------------------------------
   Static frontend
------------------------------------------------------- */

app.use(express.static("public"));

/* -------------------------------------------------------
   Global error handler
------------------------------------------------------- */

app.use((err, req, res, next) => {
  console.error("[SERVER ERROR]", err);

  if (res.headersSent) {
    return next(err);
  }

  return jsonError(
    res,
    500,
    "internal_server_error",
    "Unexpected server error"
  );
});

/* -------------------------------------------------------
   Start
------------------------------------------------------- */

app.listen(PORT, () => {
  console.log("");
  console.log("==========================================");
  console.log(" Facebook API Server v2.0.0");
  console.log("==========================================");
  console.log(`PORT: ${PORT}`);
  console.log(`GRAPH: ${GRAPH_BASE}`);
  console.log(
    `ACCESS TOKEN: ${
      FB_ACCESS_TOKEN ? "loaded ✓" : "missing ✗"
    }`
  );
  console.log(
    `PAGE ID: ${
      FB_PAGE_ID ? "loaded ✓" : "missing ✗"
    }`
  );
  console.log(
    `FB_COOKIE: ${
      process.env.FB_COOKIE ? "present ✓" : "not set"
    }`
  );
  console.log("==========================================");
  console.log("");
});
