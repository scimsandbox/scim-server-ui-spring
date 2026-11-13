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

    /*
     * Shared Ecosystem News indicator for the right-side quick-navigation dock.
     * Checks /news/index.json and compares against the shared .scimsandbox.net cookie
     * to highlight unread updates.
     */
    const NEWS_STORAGE_KEY = 'scim_news_seen';

    function readCookie(name) {
        const prefix = name + '=';
        const parts = (document.cookie || '').split(';');
        for (let i = 0; i < parts.length; i++) {
            const c = parts[i].trim();
            if (c.indexOf(prefix) === 0) {
                try {
                    return decodeURIComponent(c.substring(prefix.length));
                } catch {
                    return c.substring(prefix.length);
                }
            }
        }
        return null;
    }

    function getSeenTimestampMs() {
        const cookieVal = readCookie(NEWS_STORAGE_KEY);
        const cMs = cookieVal ? Date.parse(cookieVal) : NaN;
        return Number.isFinite(cMs) ? cMs : 0;
    }

    function initDockNewsIndicator() {
        const btn = document.querySelector('.floating-side-btn-news');
        if (!btn) return;

        const dot = btn.querySelector('.news-unread-dot');
        const feedUrl = btn.getAttribute('data-news-feed-url');
        if (!feedUrl) return;
        let cachedItems = [];

        function applyBadgeState() {
            if (!cachedItems.length) return;
            const seenMs = getSeenTimestampMs();
            const latestMs = Date.parse(cachedItems[0].publishedAt || '');
            const hasNewNews = Number.isFinite(latestMs) && latestMs > seenMs;

            if (hasNewNews) {
                const latestTitle = cachedItems[0].title || 'Ecosystem update available';
                const shortTitle = latestTitle.length > 52 ? latestTitle.substring(0, 49) + '…' : latestTitle;
                const label = `New: ${shortTitle}`;
                btn.classList.add('has-unread-news');
                btn.setAttribute('data-tooltip', label);
                btn.setAttribute('aria-label', label);
                if (dot) dot.hidden = false;
            } else {
                btn.classList.remove('has-unread-news');
                btn.setAttribute('data-tooltip', "What's New");
                btn.setAttribute('aria-label', "What's New");
                if (dot) dot.hidden = true;
            }
        }

        // Re-check on return from the website tab, which sets the cookie. focus covers a visible
        // window regaining focus; visibilitychange covers tab switches. Re-applying is idempotent.
        window.addEventListener('focus', applyBadgeState);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                applyBadgeState();
            }
        });

        fetch(feedUrl, { credentials: 'omit' })
            .then((res) => (res.ok ? res.json() : null))
            .then((data) => {
                if (!Array.isArray(data) || data.length === 0) return;
                cachedItems = data
                    .map((item) => ({ item, ms: Date.parse(item && item.publishedAt) }))
                    .filter((entry) => Number.isFinite(entry.ms))
                    .sort((a, b) => b.ms - a.ms)
                    .map((entry) => entry.item);
                applyBadgeState();
            })
            .catch(() => {
                // Feed unavailable: keep the neutral "What's New" state rather than flag stale news.
            });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDockNewsIndicator);
    } else {
        initDockNewsIndicator();
    }
})(globalThis);
