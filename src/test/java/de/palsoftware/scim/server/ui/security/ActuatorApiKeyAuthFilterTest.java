package de.palsoftware.scim.server.ui.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ActuatorApiKeyAuthFilterTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void healthEndpointsAreAlwaysPermittedWithoutApiKey() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health/readiness");
        request.setLocalPort(8080);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void configuredApiKeyRejectsMissingOrInvalidKeyWith401() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);

        MockHttpServletRequest missingKeyReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        missingKeyReq.setLocalPort(9090);
        MockHttpServletResponse missingKeyRes = new MockHttpServletResponse();
        FilterChain chain1 = mock(FilterChain.class);

        filter.doFilter(missingKeyReq, missingKeyRes, chain1);
        assertThat(missingKeyRes.getStatus()).isEqualTo(401);
        verify(chain1, never()).doFilter(missingKeyReq, missingKeyRes);

        MockHttpServletRequest wrongKeyReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        wrongKeyReq.addHeader(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "wrong-key");
        MockHttpServletResponse wrongKeyRes = new MockHttpServletResponse();
        FilterChain chain2 = mock(FilterChain.class);

        filter.doFilter(wrongKeyReq, wrongKeyRes, chain2);
        assertThat(wrongKeyRes.getStatus()).isEqualTo(401);
        verify(chain2, never()).doFilter(wrongKeyReq, wrongKeyRes);
    }

    @Test
    void configuredApiKeyAcceptsValidHeaderAndBearerTokenAndGrantsActuatorRole() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);

        MockHttpServletRequest headerReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        headerReq.addHeader(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "super-secret-key");
        MockHttpServletResponse headerRes = new MockHttpServletResponse();
        FilterChain chain1 = mock(FilterChain.class);

        filter.doFilter(headerReq, headerRes, chain1);
        verify(chain1).doFilter(headerReq, headerRes);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ACTUATOR");

        SecurityContextHolder.clearContext();

        MockHttpServletRequest bearerReq = new MockHttpServletRequest("GET", "/actuator/health");
        bearerReq.addHeader(HttpHeaders.AUTHORIZATION, "Bearer super-secret-key");
        MockHttpServletResponse bearerRes = new MockHttpServletResponse();
        FilterChain chain2 = mock(FilterChain.class);

        filter.doFilter(bearerReq, bearerRes, chain2);
        verify(chain2).doFilter(bearerReq, bearerRes);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

        SecurityContextHolder.clearContext();

        MockHttpServletRequest altHeaderReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        altHeaderReq.addHeader(ActuatorApiKeyAuthFilter.ALT_API_KEY_HEADER, "super-secret-key");
        MockHttpServletResponse altHeaderRes = new MockHttpServletResponse();
        FilterChain chain3 = mock(FilterChain.class);

        filter.doFilter(altHeaderReq, altHeaderRes, chain3);
        verify(chain3).doFilter(altHeaderReq, altHeaderRes);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void authorizedActuatorRequestReplacesContextInsteadOfMutatingExistingContextInPlace() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);

        Authentication existingUserAuth = UsernamePasswordAuthenticationToken.authenticated(
                "user@example.test",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContext existingSessionContext = SecurityContextHolder.createEmptyContext();
        existingSessionContext.setAuthentication(existingUserAuth);
        SecurityContextHolder.setContext(existingSessionContext);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/prometheus");
        request.addHeader(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "super-secret-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext()).isNotSameAs(existingSessionContext);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("actuator");
        assertThat(existingSessionContext.getAuthentication()).isSameAs(existingUserAuth);
        assertThat(existingSessionContext.getAuthentication().getName()).isEqualTo("user@example.test");
    }

    @Test
    void normalizedPathsPreventDoubleSlashAndMatrixParameterBypass() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);

        for (String variant : List.of("//actuator//prometheus", "/actuator;v=1/prometheus/")) {
            MockHttpServletRequest unauthReq = new MockHttpServletRequest("GET", variant);
            MockHttpServletResponse unauthRes = new MockHttpServletResponse();
            FilterChain unauthChain = mock(FilterChain.class);

            filter.doFilter(unauthReq, unauthRes, unauthChain);
            assertThat(unauthRes.getStatus()).as("path %s must not bypass filter", variant).isEqualTo(401);
            verify(unauthChain, never()).doFilter(unauthReq, unauthRes);
        }
    }

    @Test
    void dotSegmentsAndEncodedSlashesOnActuatorPathsAreRejectedWith400() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);

        List<String> traversalPaths = List.of(
                "/actuator/health/../prometheus",
                "/actuator/./prometheus",
                "/actuator/..;/prometheus",
                "/actuator/%2e%2e/prometheus",
                "/actuator/%2fprometheus",
                "/actuator/%5cprometheus",
                "/actuator\\prometheus",
                "/public/../actuator/prometheus");

        for (String path : traversalPaths) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", path);
            req.addHeader(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "super-secret-key");
            MockHttpServletResponse res = new MockHttpServletResponse();
            FilterChain chain = mock(FilterChain.class);

            filter.doFilter(req, res, chain);

            assertThat(res.getStatus()).as("traversal path %s must return 400", path).isEqualTo(400);
            verify(chain, never()).doFilter(req, res);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }

    @Test
    void blankApiKeyPermitsDedicatedManagementPortAndDeniesMainAppPort() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("", 9090, 8080);

        MockHttpServletRequest mainPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        mainPortReq.setLocalPort(8080);
        MockHttpServletResponse mainPortRes = new MockHttpServletResponse();
        FilterChain mainChain = mock(FilterChain.class);

        filter.doFilter(mainPortReq, mainPortRes, mainChain);
        assertThat(mainPortRes.getStatus()).isEqualTo(403);
        verify(mainChain, never()).doFilter(mainPortReq, mainPortRes);

        MockHttpServletRequest mgmtPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        mgmtPortReq.setLocalPort(9090);
        MockHttpServletResponse mgmtPortRes = new MockHttpServletResponse();
        FilterChain mgmtChain = mock(FilterChain.class);

        filter.doFilter(mgmtPortReq, mgmtPortRes, mgmtChain);
        verify(mgmtChain).doFilter(mgmtPortReq, mgmtPortRes);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void nonActuatorPathsBypassFilter() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/workspaces");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
