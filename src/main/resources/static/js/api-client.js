/*
 * Shared API client and UI/URL helpers for the management UI, loaded first by both
 * index.html and workspace.html before dock-news.js, index.js, and workspace.js.
 * Session-expiry handling lives here so a 401 behaves identically on every page.
 */
(function (global) {
    const CSRF_TOKEN = document.querySelector('meta[name="_csrf"]')?.content;
    const CSRF_HEADER = document.querySelector('meta[name="_csrf_header"]')?.content || 'X-CSRF-TOKEN';

    let sessionExpired = false;

    function esc(value) {
        if (value == null) {
            return '';
        }
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function parseHttpUrl(rawUrl) {
        if (!rawUrl) {
            return null;
        }
        try {
            const parsed = new URL(String(rawUrl).trim(), global.location.href);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed;
            }
        } catch {
            // Invalid URL
        }
        return null;
    }

    function sanitizeHttpUrl(rawUrl) {
        return parseHttpUrl(rawUrl)?.href || null;
    }

    // The reload is asynchronous, so callers still receive the 401 and paint their own failure text
    // ("Failed to load users.", "Request failed") in the moment before the navigation commits. Cover
    // the page first so that flash reads as an explanation instead of a fault. This deliberately does
    // not reuse #actionOverlay, which runBlockingAction hides again in its finally block.
    function showSigningInOverlay() {
        let overlay = document.getElementById('sessionReloadOverlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'sessionReloadOverlay';
            overlay.className = 'blocking-overlay session-reload-overlay';
            overlay.setAttribute('role', 'status');

            const card = document.createElement('div');
            card.className = 'blocking-overlay-card';

            const spinner = document.createElement('div');
            spinner.className = 'blocking-overlay-spinner';

            const copyWrap = document.createElement('div');
            const title = document.createElement('div');
            title.className = 'blocking-overlay-title';
            title.textContent = 'Session expired';

            const copy = document.createElement('div');
            copy.className = 'blocking-overlay-copy';
            copy.textContent = 'Signing you back in…';

            copyWrap.appendChild(title);
            copyWrap.appendChild(copy);
            card.appendChild(spinner);
            card.appendChild(copyWrap);
            overlay.appendChild(card);
            document.body.appendChild(overlay);
        }
        overlay.classList.add('active');
    }

    function signInAgain() {
        showSigningInOverlay();
        window.location.reload();
    }

    function handleSessionExpired() {
        if (sessionExpired) {
            return;
        }
        sessionExpired = true;
        // Reloading while an editor is open would discard everything the user has typed, so show a
        // banner instead and let them copy their work out before triggering the login round trip.
        const banner = document.getElementById('sessionExpiredBanner');
        if (banner && document.querySelector('.modal-backdrop.active')) {
            banner.classList.add('active');
            banner.setAttribute('aria-hidden', 'false');
            // Lets the stylesheet keep an open dialog clear of the fixed banner.
            document.body.classList.add('session-expired');
            return;
        }
        signInAgain();
    }

    async function apiFetch(url, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        const headers = new Headers(options.headers || {});
        if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && method !== 'TRACE' && CSRF_TOKEN) {
            headers.set(CSRF_HEADER, CSRF_TOKEN);
        }
        const res = await fetch(url, {...options, headers, credentials: 'same-origin'});
        if (res.status === 401) {
            handleSessionExpired();
        }
        return res;
    }

    document.addEventListener('click', (event) => {
        const trigger = event.target instanceof Element
            ? event.target.closest('[data-action="sign-in-again"]')
            : null;
        if (trigger) {
            event.preventDefault();
            signInAgain();
        }
    });

    global.apiFetch = apiFetch;
    global.signInAgain = signInAgain;
    global.esc = esc;
    global.parseHttpUrl = parseHttpUrl;
    global.sanitizeHttpUrl = sanitizeHttpUrl;
})(globalThis);
