package de.palsoftware.scim.server.ui.utils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Shared HTTP(S) URL validation and normalization helpers used by UI model rendering
 * and Content-Security-Policy origin extraction.
 */
public final class HttpUrlUtils {

    private HttpUrlUtils() {
    }

    /**
     * Validates {@code rawUrl} as an absolute {@code http} or {@code https} URL with a host
     * and strips trailing slashes so fixed path suffixes never produce doubled slashes.
     */
    public static String normalizeHttpUrl(String rawUrl, String errorMessage) {
        String trimmed = stripTrailingSlashes(rawUrl);
        if (parseAbsoluteHttpUri(trimmed) != null) {
            return trimmed;
        }
        throw new IllegalStateException(errorMessage);
    }

    /**
     * Extracts the lowercase {@code scheme://host[:port]} origin from {@code rawUrl} if it is a
     * valid absolute {@code http} or {@code https} URL, or {@code null} otherwise.
     */
    public static String extractHttpOrigin(String rawUrl) {
        URI uri = parseAbsoluteHttpUri(rawUrl == null ? null : rawUrl.trim());
        if (uri == null) {
            return null;
        }
        String lowerScheme = uri.getScheme().toLowerCase(Locale.ROOT);
        String lowerHost = uri.getHost().toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        return port > 0
                ? lowerScheme + "://" + lowerHost + ":" + port
                : lowerScheme + "://" + lowerHost;
    }

    private static URI parseAbsoluteHttpUri(String candidate) {
        if (candidate == null || candidate.isEmpty()) {
            return null;
        }
        try {
            URI uri = new URI(candidate);
            String scheme = uri.getScheme();
            boolean http = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
            if (http && uri.getHost() != null) {
                return uri;
            }
        } catch (URISyntaxException ex) {
            // Invalid URI
        }
        return null;
    }

    private static String stripTrailingSlashes(String rawUrl) {
        String normalized = rawUrl == null ? "" : rawUrl.trim();
        int end = normalized.length();
        while (end > 0 && normalized.charAt(end - 1) == '/') {
            end--;
        }
        return normalized.substring(0, end);
    }
}
