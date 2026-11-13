package de.palsoftware.scim.server.ui.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Protects {@code /actuator/**} endpoints while keeping liveness/readiness probes accessible.
 *
 * <ul>
 *   <li>{@code /actuator/health} and {@code /actuator/health/**} are always permitted; if a valid
 *       API key is presented (or the request arrives on the dedicated management port when no key is
 *       configured), {@code ROLE_ACTUATOR} is granted so {@code show-components: when_authorized}
 *       can expose details only to authorized callers.</li>
 *   <li>When {@code app.security.actuator.api-key} is configured, all other {@code /actuator/**}
 *       endpoints require a constant-time SHA-256 match against {@code X-Actuator-Api-Key} or
 *       {@code Authorization: Bearer <key>}.</li>
 *   <li>When {@code app.security.actuator.api-key} is blank, other {@code /actuator/**} endpoints
 *       are permitted ONLY on the dedicated management port ({@code request.getLocalPort() == managementPort})
 *       and rejected on the main application port.</li>
 * </ul>
 */
public class ActuatorApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-Actuator-Api-Key";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_ACTUATOR = "ROLE_ACTUATOR";

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

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = resolvePath(request);
        return !"/actuator".equals(path) && !path.startsWith("/actuator/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = resolvePath(request);
        boolean isHealthEndpoint = "/actuator/health".equals(path) || path.startsWith("/actuator/health/");
        boolean authorized = isAuthorizedActuatorCaller(request);

        if (authorized) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    "actuator",
                    null,
                    List.of(new SimpleGrantedAuthority(ROLE_ACTUATOR)));
            SecurityContextHolder.getContext().setAuthentication(auth);
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
            if (candidate == null || candidate.isBlank()) {
                return false;
            }
            return MessageDigest.isEqual(expectedKeyDigest, sha256(candidate.trim()));
        }
        return managementPort > 0
                && managementPort != serverPort
                && request.getLocalPort() == managementPort;
    }

    private static String extractCandidateKey(HttpServletRequest request) {
        String headerKey = request.getHeader(API_KEY_HEADER);
        if (headerKey != null && !headerKey.isBlank()) {
            return headerKey;
        }
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null
                && authorization.length() > BEARER_PREFIX.length()
                && authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authorization.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private static String resolvePath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null) {
            return "/";
        }
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }
        return uri.isEmpty() ? "/" : uri;
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
