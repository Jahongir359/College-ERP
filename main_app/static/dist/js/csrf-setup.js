/* Global CSRF setup for jQuery AJAX + fetch.
 *
 * Loaded once from base.html, after jQuery. After this script runs:
 *   - Every $.ajax() / $.post() call on unsafe methods (POST/PUT/PATCH/DELETE)
 *     gets the X-CSRFToken header automatically.
 *   - window.apiPost(url, body) is a fetch() wrapper that does the same.
 *
 * This removes the need for @csrf_exempt on Django views handling internal
 * AJAX. Each page no longer needs its own getCookie() + headers boilerplate.
 */
(function () {
  'use strict';

  function getCookie(name) {
    if (!document.cookie) return null;
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const c = cookies[i].trim();
      if (c.substring(0, name.length + 1) === name + '=') {
        return decodeURIComponent(c.substring(name.length + 1));
      }
    }
    return null;
  }

  const csrftoken = getCookie('csrftoken');
  // Expose for legacy pages still referencing window.csrftoken.
  window.csrftoken = csrftoken;
  window.getCookie = getCookie;

  // ── jQuery hook ────────────────────────────────────────────────────────────
  if (window.jQuery) {
    window.jQuery.ajaxSetup({
      beforeSend: function (xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !settings.crossDomain) {
          xhr.setRequestHeader('X-CSRFToken', csrftoken);
        }
      }
    });
  }

  // ── fetch() helpers ────────────────────────────────────────────────────────
  function buildHeaders(extra) {
    const h = new Headers(extra || {});
    if (csrftoken) h.set('X-CSRFToken', csrftoken);
    return h;
  }

  window.apiPost = function (url, body, opts) {
    opts = opts || {};
    const headers = buildHeaders(opts.headers);
    let payload = body;
    if (body && typeof body === 'object' && !(body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
      payload = JSON.stringify(body);
    }
    return fetch(url, {
      method: opts.method || 'POST',
      credentials: 'same-origin',
      headers: headers,
      body: payload,
    });
  };

  window.apiGet = function (url, opts) {
    opts = opts || {};
    return fetch(url, {
      method: 'GET',
      credentials: 'same-origin',
      headers: buildHeaders(opts.headers),
    });
  };
})();
