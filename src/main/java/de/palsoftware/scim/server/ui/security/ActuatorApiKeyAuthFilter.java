package de.palsoftware.scim.server.ui.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;

/**
 * Protects {@code /actuator/**} endpoints while keeping liveness/readiness probes accessible.
 *
 * <ul>
 *   <li>{@code /actuator/health} and {@code /actuator/health/**} are always permitted; if a valid
 *       API key is presented (or the request arrives on the dedicated management port when no key is
 *       configured), {@code ROLE_ACTUATOR} is granted on a fresh request-scoped {@link SecurityContext}
 *       so {@code show-components: when_authorized} with {@code roles: ACTUATOR} exposes details only
 *       to authorized actuator callers without mutating any existing user session.</li>
 *   <li>When {@code app.security.actuator.api-key} is configured, all other {@code /actuator/**}
 *       endpoints require a constant-time SHA-256 match against {@code X-Actuator-Api-Key},
 *       {@code X-API-Key}, or {@code Authorization: Bearer <key>}.</li>
 *   <li>When {@code app.security.actuator.api-key} is blank, other {@code /actuator/**} endpoints
 *       are permitted ONLY on the dedicated management port ({@code request.getLocalPort() == managementPort})
 *       and rejected on the main application port.</li>
 * </ul>
 */
public class ActuatorApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-Actuator-Api-Key";
    public static final String ALT_API_KEY_HEADER = "X-API-Key";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_ACTUATOR = "ROLE_ACTUATOR";
    private static final String CACHED_PATH_ATTR = ActuatorApiKeyAuthFilter.class.getName() + ".PATH";
    private static final String TRAVERSAL_SENTINEL = "__INVALID_ACTUATOR_TRAVERSAL__";
    private static final byte[] EMPTY_DIGEST = sha256("");

    private final byte[] expectedKeyDigest;
    private final int managementPort;
    private final int serverPort;

    public ActuatorApiKeyAuthFilter(String configuredApiKey, int managementPort, int serverPort) {
        this.expectedKeyDigest = (configuredApiKey != null && !configuredApiKey.isBlank())
                ? sha256(configuredApiKey.trim())
                : null;
        this.managementPort = managementPort;
        this.serverPort = serverPort;
    }

    static boolean isActuatorRequest(HttpServletRequest request) {
        String path = resolvePath(request);
        return TRAVERSAL_SENTINEL.equals(path) || "/actuator".equals(path) || path.startsWith("/actuator/");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !isActuatorRequest(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = resolvePath(request);
        if (TRAVERSAL_SENTINEL.equals(path)) {
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        boolean isHealthEndpoint = "/actuator/health".equals(path) || path.startsWith("/actuator/health/");

        if (isAuthorizedActuatorCaller(request)) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "actuator",
                    null,
                    List.of(new SimpleGrantedAuthority(ROLE_ACTUATOR))));
            SecurityContextHolder.setContext(context);
            filterChain.doFilter(request, response);
            return;
        }

        if (isHealthEndpoint) {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityContextHolder.clearContext();
        response.setStatus(expectedKeyDigest != null
                ? HttpServletResponse.SC_UNAUTHORIZED
                : HttpServletResponse.SC_FORBIDDEN);
    }

    private boolean isAuthorizedActuatorCaller(HttpServletRequest request) {
        if (expectedKeyDigest != null) {
            String candidate = extractCandidateKey(request);
            if (candidate == null) {
                MessageDigest.isEqual(expectedKeyDigest, EMPTY_DIGEST);
                return false;
            }
            return MessageDigest.isEqual(expectedKeyDigest, sha256(candidate));
        }
        return managementPort > 0
                && managementPort != serverPort
                && request.getLocalPort() == managementPort;
    }

    private static String extractCandidateKey(HttpServletRequest request) {
        String actuatorHeaderKey = trimToNull(request.getHeader(API_KEY_HEADER));
        if (actuatorHeaderKey != null) {
            return actuatorHeaderKey;
        }
        String altHeaderKey = trimToNull(request.getHeader(ALT_API_KEY_HEADER));
        if (altHeaderKey != null) {
            return altHeaderKey;
        }
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null
                && authorization.length() > BEARER_PREFIX.length()
                && authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return trimToNull(authorization.substring(BEARER_PREFIX.length()));
        }
        return null;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    static String resolvePath(HttpServletRequest request) {
        Object cached = request.getAttribute(CACHED_PATH_ATTR);
        if (cached instanceof String cachedPath) {
            return cachedPath;
        }
        String normalized = computeNormalizedPath(request);
        request.setAttribute(CACHED_PATH_ATTR, normalized);
        return normalized;
    }

    private static String computeNormalizedPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null || uri.isEmpty()) {
            return "/";
        }
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }
        if (containsTraversalSegment(uri)) {
            return uri.toLowerCase(Locale.ROOT).contains("actuator") ? TRAVERSAL_SENTINEL : uri;
        }
        StringBuilder sb = new StringBuilder(uri.length());
        boolean inMatrixParam = false;
        boolean prevSlash = false;
        for (int i = 0; i < uri.length(); i++) {
            char ch = uri.charAt(i);
            if (ch == '/') {
                inMatrixParam = false;
                if (!prevSlash) {
                    sb.append('/');
                    prevSlash = true;
                }
            } else if (ch == ';') {
                inMatrixParam = true;
            } else if (!inMatrixParam) {
                sb.append(ch);
                prevSlash = false;
            }
        }
        while (sb.length() > 1 && sb.charAt(sb.length() - 1) == '/') {
            sb.setLength(sb.length() - 1);
        }
        return sb.isEmpty() ? "/" : sb.toString();
    }

    private static boolean containsTraversalSegment(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("\\")) {
            return true;
        }
        int start = 0;
        int len = path.length();
        while (start <= len) {
            int slash = path.indexOf('/', start);
            int end = slash < 0 ? len : slash;
            int semicolon = path.indexOf(';', start);
            int cleanEnd = (semicolon >= start && semicolon < end) ? semicolon : end;
            int segLen = cleanEnd - start;
            if ((segLen == 1 && path.charAt(start) == '.')
                    || (segLen == 2 && path.charAt(start) == '.' && path.charAt(start + 1) == '.')) {
                return true;
            }
            if (slash < 0) {
                break;
            }
            start = slash + 1;
        }
        return false;
    }

    private static byte[] sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        }
    }
}
