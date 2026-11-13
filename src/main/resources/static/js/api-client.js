/*
 * Shared API client for the management UI, loaded by both index.html and workspace.html.
 * Session-expiry handling lives here so a 401 behaves identically on every page.
 */
(function (global) {
    const CSRF_TOKEN = document.querySelector('meta[name="_csrf"]')?.content;
    const CSRF_HEADER = document.querySelector('meta[name="_csrf_header"]')?.content || 'X-CSRF-TOKEN';

    let sessionExpired = false;

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
            overlay.innerHTML = '<div class="blocking-overlay-card">'
                + '<div class="blocking-overlay-spinner"></div>'
                + '<div>'
                + '<div class="blocking-overlay-title">Session expired</div>'
                + '<div class="blocking-overlay-copy">Signing you back in…</div>'
                + '</div></div>';
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

    global.apiFetch = apiFetch;
    global.signInAgain = signInAgain;
})(globalThis);
