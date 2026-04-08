//! Resources route handler module.
//!
//! Provides the `/resources` page, which uses JavaScript `fetch` to call three
//! API endpoints and display their results:
//!
//! - `GET /api/me` — user identity; a `404` means the session is not
//!   recognised by the upstream API (treated as "not authenticated").
//! - `GET /api/protected/resource1` — fetched in parallel with `resource2`.
//! - `GET /api/protected/resource2` — fetched in parallel with `resource1`.
//!
//! All three calls are initiated client-side after the HTML shell is delivered,
//! so the server-side handler is intentionally thin: it just returns the page
//! skeleton and the embedded script does the rest.
//!
//! # Authentication
//!
//! The route itself requires a valid [`AuthSession`] — unauthenticated visitors
//! are redirected to the OIDC login flow before they ever see the page.
//!
//! # Error presentation
//!
//! | Condition                        | What the page shows                          |
//! |----------------------------------|----------------------------------------------|
//! | `/api/me` returns `404`          | "Not authenticated" banner                   |
//! | Any other non-`2xx` status       | Status code + HTTP status description        |
//! | Network / fetch error            | Error message string                         |
//! | `resource1` or `resource2` error | Inline status description in that card       |

use axum::response::Html;

/// Resources page handler.
///
/// Returns an HTML page that fetches `/api/me`, `/api/protected/resource1`
/// and `/api/protected/resource2` client-side.  The two protected resource
/// calls are issued with `Promise.all` so they run in parallel.
///
/// # Route
///
/// - `GET /resources`
///
/// # Authentication
///
/// Requires a valid [`AuthSession`].  Unauthenticated users are redirected to
/// the OIDC provider automatically.
pub async fn resources() -> Html<&'static str> {
    Html(RESOURCES_HTML)
}

// ── HTML / JS shell ───────────────────────────────────────────────────────────
//
// Kept as a `&'static str` constant so it is allocated once at compile time
// and never heap-copied per request.

static RESOURCES_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Resources</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: Arial, sans-serif;
      background: #f0f2f5;
      padding: 40px 20px;
      color: #333;
    }

    h1 {
      text-align: center;
      margin-bottom: 32px;
      color: #222;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 24px;
      max-width: 1100px;
      margin: 0 auto 32px;
    }

    .card {
      background: #fff;
      border-radius: 10px;
      padding: 24px;
      box-shadow: 0 2px 8px rgba(0,0,0,.08);
      border-left: 5px solid #6c757d;
      transition: border-color .2s;
    }
    .card.loading  { border-color: #adb5bd; }
    .card.success  { border-color: #28a745; }
    .card.error    { border-color: #dc3545; }
    .card.unauthed { border-color: #fd7e14; }

    .card h2 {
      font-size: 1rem;
      font-weight: 700;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-badge {
      display: inline-block;
      font-size: .7rem;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 999px;
      background: #e9ecef;
      color: #495057;
    }
    .success  .status-badge { background: #d4edda; color: #155724; }
    .error    .status-badge { background: #f8d7da; color: #721c24; }
    .unauthed .status-badge { background: #fde5cc; color: #7d3a00; }

    .body-pre {
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 6px;
      padding: 12px;
      font-family: monospace;
      font-size: .8rem;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 320px;
      overflow-y: auto;
      margin-top: 10px;
      color: #212529;
    }

    .spinner {
      display: inline-block;
      width: 16px;
      height: 16px;
      border: 2px solid #adb5bd;
      border-top-color: #495057;
      border-radius: 50%;
      animation: spin .7s linear infinite;
      vertical-align: middle;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .message {
      font-size: .92rem;
      margin-top: 8px;
    }

    .nav {
      text-align: center;
      margin-top: 8px;
    }
    .nav a {
      color: #0066cc;
      text-decoration: none;
      margin: 0 12px;
      font-size: .95rem;
    }
    .nav a:hover { text-decoration: underline; }

    .unauthenticated-banner {
      max-width: 1100px;
      margin: 0 auto 28px;
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-left: 5px solid #fd7e14;
      border-radius: 8px;
      padding: 16px 20px;
      display: none;
      color: #664d03;
      font-size: .95rem;
    }
    .unauthenticated-banner strong { display: block; margin-bottom: 4px; font-size: 1rem; }
  </style>
</head>
<body>

<h1>📦 Resources</h1>

<div class="unauthenticated-banner" id="unauthed-banner">
  <strong>⚠️ Not authenticated on the API server</strong>
  The upstream API does not recognise your session (<code>/api/me</code> returned 404).
  The resource calls below may also fail.
</div>

<div class="grid">
  <!-- /api/me -->
  <div class="card loading" id="card-me">
    <h2>
      👤 /api/me
      <span class="status-badge" id="badge-me">loading…</span>
    </h2>
    <div id="body-me"><span class="spinner"></span></div>
  </div>

  <!-- /api/protected/resource1 -->
  <div class="card loading" id="card-r1">
    <h2>
      🗂 /api/protected/resource1
      <span class="status-badge" id="badge-r1">loading…</span>
    </h2>
    <div id="body-r1"><span class="spinner"></span></div>
  </div>

  <!-- /api/protected/resource2 -->
  <div class="card loading" id="card-r2">
    <h2>
      🗂 /api/protected/resource2
      <span class="status-badge" id="badge-r2">loading…</span>
    </h2>
    <div id="body-r2"><span class="spinner"></span></div>
  </div>
</div>

<div class="nav">
  <a href="/">← Home</a>
  <a href="/tokeninfo">Token Info</a>
  <a href="/auth/logout">Logout</a>
</div>

<script>
"use strict";

// ── HTTP status descriptions ──────────────────────────────────────────────────
const STATUS_TEXT = {
  100: "Continue",
  101: "Switching Protocols",
  200: "OK",
  201: "Created",
  204: "No Content",
  301: "Moved Permanently",
  302: "Found",
  304: "Not Modified",
  400: "Bad Request",
  401: "Unauthorized",
  402: "Payment Required",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  408: "Request Timeout",
  409: "Conflict",
  410: "Gone",
  422: "Unprocessable Entity",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};

function statusDescription(code) {
  return STATUS_TEXT[code] ? `${code} ${STATUS_TEXT[code]}` : `${code}`;
}

// ── Card helpers ──────────────────────────────────────────────────────────────

/**
 * Render a successful API response into a card.
 * Tries to pretty-print JSON; falls back to raw text.
 */
function renderSuccess(cardId, badgeId, bodyId, status, text) {
  const card  = document.getElementById(cardId);
  const badge = document.getElementById(badgeId);
  const body  = document.getElementById(bodyId);

  card.className  = "card success";
  badge.textContent = statusDescription(status);

  let display = text;
  try {
    display = JSON.stringify(JSON.parse(text), null, 2);
  } catch (_) { /* not JSON — show as-is */ }

  const pre = document.createElement("pre");
  pre.className = "body-pre";
  pre.textContent = display || "(empty response)";
  body.replaceChildren(pre);
}

/**
 * Render an error (non-2xx or network failure) into a card.
 *
 * @param {string}      cardId
 * @param {string}      badgeId
 * @param {string}      bodyId
 * @param {number|null} status   - HTTP status code, or null for network errors
 * @param {string}      text     - Response body or error message
 */
function renderError(cardId, badgeId, bodyId, status, text) {
  const card  = document.getElementById(cardId);
  const badge = document.getElementById(badgeId);
  const body  = document.getElementById(bodyId);

  card.className = "card error";
  badge.textContent = status !== null ? statusDescription(status) : "network error";

  const msg = document.createElement("p");
  msg.className = "message";
  msg.textContent = text || statusDescription(status);
  body.replaceChildren(msg);
}

/**
 * Render the "not authenticated" state for the /api/me card (404 case).
 */
function renderUnauthenticated(cardId, badgeId, bodyId) {
  const card  = document.getElementById(cardId);
  const badge = document.getElementById(badgeId);
  const body  = document.getElementById(bodyId);

  card.className = "card unauthed";
  badge.textContent = "404 Not Found";

  const msg = document.createElement("p");
  msg.className = "message";
  msg.textContent =
    "The API server does not recognise your session. " +
    "You may need to log in on the upstream API.";
  body.replaceChildren(msg);

  // Also show the top-level banner
  document.getElementById("unauthed-banner").style.display = "block";
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

/**
 * Fetch a URL and return { status, text } or throw on network error.
 * Never throws on HTTP error status — callers decide what to do with it.
 */
async function apiFetch(url) {
  const resp = await fetch(url, { credentials: "same-origin" });
  const text = await resp.text();
  return { status: resp.status, text };
}

// ── Main fetch logic ──────────────────────────────────────────────────────────

async function loadAll() {
  // ── /api/me (sequential first — its 404 drives the banner) ───────────────
  const mePromise = apiFetch("/api/me")
    .then(({ status, text }) => {
      if (status === 404) {
        renderUnauthenticated("card-me", "badge-me", "body-me");
      } else if (status >= 200 && status < 300) {
        renderSuccess("card-me", "badge-me", "body-me", status, text);
      } else {
        renderError("card-me", "badge-me", "body-me", status, text);
      }
    })
    .catch((err) => {
      renderError("card-me", "badge-me", "body-me", null, err.message);
    });

  // ── /api/protected/resource1 and /api/protected/resource2 in parallel ─────
  const r1Promise = apiFetch("/api/protected/resource1")
    .then(({ status, text }) => {
      if (status >= 200 && status < 300) {
        renderSuccess("card-r1", "badge-r1", "body-r1", status, text);
      } else {
        renderError("card-r1", "badge-r1", "body-r1", status, text);
      }
    })
    .catch((err) => {
      renderError("card-r1", "badge-r1", "body-r1", null, err.message);
    });

  const r2Promise = apiFetch("/api/protected/resource2")
    .then(({ status, text }) => {
      if (status >= 200 && status < 300) {
        renderSuccess("card-r2", "badge-r2", "body-r2", status, text);
      } else {
        renderError("card-r2", "badge-r2", "body-r2", status, text);
      }
    })
    .catch((err) => {
      renderError("card-r2", "badge-r2", "body-r2", null, err.message);
    });

  // Wait for all three (errors are handled inside each branch above).
  await Promise.all([mePromise, r1Promise, r2Promise]);
}

// Kick everything off as soon as the script runs (DOM is already parsed at
// this point because the <script> tag is at the bottom of <body>).
loadAll();
</script>
</body>
</html>
"#;
