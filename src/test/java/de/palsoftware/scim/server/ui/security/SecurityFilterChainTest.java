package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.ui.TestClientRegistrationConfig;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers the unauthenticated edges of {@link SecurityConfig}: API calls must fail closed with a bare
 * 401 so the UI can restart the login flow, page navigations must keep redirecting to the IdP, and only
 * page navigations may be replayed after login.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClientRegistrationConfig.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "spring.jpa.open-in-view=false",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret",
    "AUTH0_REDIRECT_URI=https://ui.scimsandbox.net/login/oauth2/code/auth0",
    "AUTH0_ISSUER_URI=https://test.auth0.com/",
    "APP_WEBSITE_URL=https://website.example.test"
})
class SecurityFilterChainTest extends PostgresIntegrationTestSupport {

    private static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
    private static final String LOGIN_URL_PATTERN = "**/oauth2/authorization/auth0";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void unauthenticatedApiRequest_returnsEmpty401() throws Exception {
        mockMvc.perform(get("/api/workspaces").accept(MediaType.ALL))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(""));
    }

    @Test
    void unauthenticatedApiRequest_returns401ForJsonAndXhrClients() throws Exception {
        mockMvc.perform(get("/api/workspaces").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/workspaces").header("X-Requested-With", "XMLHttpRequest"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unauthenticatedPageNavigation_redirectsToIdentityProvider() throws Exception {
        mockMvc.perform(get("/workspaces/" + UUID.randomUUID()).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern(LOGIN_URL_PATTERN));
    }

    /**
     * Guards the entry-point fallback: {@code DelegatingAuthenticationEntryPoint} uses its first registered
     * mapping as the no-match default, so without an explicit catch-all the /api/** 401 silently becomes the
     * application-wide default and every non-HTML client stops being redirected to the IdP.
     */
    @Test
    void unauthenticatedRootRequest_redirectsEvenWithoutAnHtmlAcceptHeader() throws Exception {
        mockMvc.perform(get("/").accept(MediaType.ALL))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern(LOGIN_URL_PATTERN));

        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern(LOGIN_URL_PATTERN));
    }

    @Test
    void apiRequestIsNotSavedAsThePostLoginTarget() throws Exception {
        assertNotSaved(mockMvc.perform(get("/api/workspaces").accept(MediaType.ALL))
                .andExpect(status().isUnauthorized()), "a 401'd API call");
    }

    /**
     * Supplying our own RequestCache discards Spring's default saved-request matcher, so the exclusions
     * that matter have to be restated in {@link SecurityConfig}. Only the XHR one is asserted here: the
     * favicon clause is unfalsifiable while /favicon.* is permitAll, since such a request never reaches
     * ExceptionTranslationFilter at all.
     */
    @Test
    void xhrRequestsAreNotSavedAsThePostLoginTarget() throws Exception {
        assertNotSaved(mockMvc.perform(get("/workspaces/" + UUID.randomUUID())
                .header("X-Requested-With", "XMLHttpRequest")), "an XHR");
    }

    @Test
    void staticAssetsReferencedByTheTemplatesArePublic() throws Exception {
        mockMvc.perform(get("/favicon.svg")).andExpect(status().isOk());
        mockMvc.perform(get("/fonts/fonts.css")).andExpect(status().isOk());
        mockMvc.perform(get("/css/workspace.css")).andExpect(status().isOk());
        mockMvc.perform(get("/css/error.css")).andExpect(status().isOk());
        // workspace.js and index.js depend on these files existing; a packaging slip would break
        // page behaviour or 401 handling while leaving backend tests green.
        mockMvc.perform(get("/js/api-client.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("global.apiFetch")));
        mockMvc.perform(get("/js/index.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("loadWorkspaces")));
    }

    @Test
    void actuatorHealthBypassesOidcRedirectWhileOtherActuatorEndpointsAreDeniedOnMainPortWithoutKey() throws Exception {
        // With management.server.port=9090 in application.yml, MockMvc (main context) does not mount
        // Actuator handlers, so passing security reaches DispatcherServlet (404) instead of 302/401/403.
        int healthStatus = mockMvc.perform(get("/actuator/health"))
                .andReturn()
                .getResponse()
                .getStatus();
        assertThat(healthStatus).isNotIn(302, 401, 403);

        mockMvc.perform(get("/actuator/prometheus"))
                .andExpect(status().isForbidden());
    }

    private static void assertNotSaved(ResultActions result, String what) throws Exception {
        MockHttpSession session = (MockHttpSession) result.andReturn().getRequest().getSession(false);
        assertThat(session == null || session.getAttribute(SAVED_REQUEST) == null)
                .as("%s must not become the post-login landing page", what)
                .isTrue();
    }

    @Test
    void pageNavigationIsSavedAsThePostLoginTarget() throws Exception {
        MockHttpSession session = (MockHttpSession) mockMvc.perform(get("/").accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andReturn()
                .getRequest()
                .getSession(false);

        assertThat(session).isNotNull();
        assertThat(session.getAttribute(SAVED_REQUEST))
                .as("page navigations must be replayed after login")
                .isNotNull();
    }

    @Test
    void preDeployOidcSessionWithoutEmailClaim_returns401InsteadOf500OnApiAndInvalidatesSession() throws Exception {
        MockHttpSession legacySession = buildPreDeployOidcSessionWithoutEmail();

        mockMvc.perform(get("/api/workspaces")
                        .session(legacySession)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        assertThat(legacySession.isInvalid()).isTrue();
    }

    @Test
    void authErrorPageIsPublicAndDoesNotLoopToIdentityProvider() throws Exception {
        mockMvc.perform(get("/auth-error").param("reason", "access_denied").accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sign-in was denied")))
                .andExpect(content().string(containsString("href=\"/css/error.css\"")))
                .andExpect(content().string(containsString("href=\"/oauth2/authorization/auth0?prompt=login\"")));
    }

    @Test
    void loginCallbackWithoutSavedAuthorizationRequest_redirectsToAuthError() throws Exception {
        mockMvc.perform(get("/login/oauth2/code/auth0").param("code", "x").param("state", "y"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/auth-error?reason=authorization_request_not_found"));
    }

    @Test
    void oauth2AuthorizationRequest_includesPromptLoginOnlyWhenRequested() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/auth0").param("prompt", "login"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("prompt=login")));

        mockMvc.perform(get("/oauth2/authorization/auth0"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString("prompt="))));

        mockMvc.perform(get("/oauth2/authorization/auth0").param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString("prompt="))));
    }

    @Test
    void authErrorPageWithInvalidOidcSession_returns200AndInvalidatesStaleSession() throws Exception {
        MockHttpSession legacySession = buildPreDeployOidcSessionWithoutEmail();

        mockMvc.perform(get("/auth-error")
                        .param("reason", "invalid_token")
                        .session(legacySession)
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account profile incomplete")));

        assertThat(legacySession.isInvalid()).isTrue();
    }

    @Test
    void oidcSessionWithValidEmailAndEmailVerifiedFalse_isNotEvictedBySessionFilter() throws Exception {
        MockHttpSession session = buildOidcSession(
                Map.of("sub", "auth0|unverified-user", "email", "user@example.test", "email_verified", false));

        mockMvc.perform(get("/api/workspaces")
                        .session(session)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        assertThat(session.isInvalid()).isFalse();
    }

    @Test
    void preDeployOidcSessionWithoutEmailClaim_redirectsToIdentityProviderInsteadOf500OnUiNavigation() throws Exception {
        MockHttpSession legacySession = buildPreDeployOidcSessionWithoutEmail();

        mockMvc.perform(get("/")
                        .session(legacySession)
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern(LOGIN_URL_PATTERN));

        assertThat(legacySession.isInvalid()).isTrue();
    }

    @ParameterizedTest
    @CsvSource({
            "400, Bad request, The request could not be understood.",
            "403, Access denied, You do not have permission to perform this action",
            "404, Page not found, The page you requested could not be found.",
            "405, Method not allowed, This action is not supported for the requested address.",
            "500, Something went wrong, An unexpected server error occurred."
    })
    void customErrorPageRendersStatusWithoutReflectingUntrustedDetails(
            int statusCode, String expectedTitle, String expectedMessageSnippet) throws Exception {
        mockMvc.perform(get("/error")
                        .accept(MediaType.TEXT_HTML)
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, statusCode)
                        .requestAttr(RequestDispatcher.ERROR_MESSAGE, "<script>leaked-internal-detail</script>"))
                .andExpect(status().is(statusCode))
                .andExpect(content().string(containsString("<title>" + expectedTitle + " — SCIM Server Manager</title>")))
                .andExpect(content().string(containsString("Error " + statusCode)))
                .andExpect(content().string(containsString(expectedTitle)))
                .andExpect(content().string(containsString(expectedMessageSnippet)))
                .andExpect(content().string(containsString("href=\"/\"")))
                .andExpect(content().string(not(containsString("Whitelabel Error Page"))))
                .andExpect(content().string(not(containsString("leaked-internal-detail"))));
    }

    @Test
    void directErrorPageVisitHides999StatusAndWhitelabel() throws Exception {
        mockMvc.perform(get("/error").accept(MediaType.TEXT_HTML))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("Something went wrong")))
                .andExpect(content().string(containsString("The request could not be completed.")))
                .andExpect(content().string(containsString("href=\"/\"")))
                .andExpect(content().string(not(containsString("999"))))
                .andExpect(content().string(not(containsString("Whitelabel Error Page"))));
    }

    @Test
    void errorEndpointPreservesJsonNegotiation() throws Exception {
        mockMvc.perform(get("/error")
                        .accept(MediaType.APPLICATION_JSON)
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 404))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(404));
    }

    private static MockHttpSession buildPreDeployOidcSessionWithoutEmail() {
        return buildOidcSession(
                Map.of("sub", "auth0|legacy-user", "preferred_username", "legacy@example.test"));
    }

    private static MockHttpSession buildOidcSession(Map<String, Object> claims) {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken(
                "oidc-id-token",
                now,
                now.plusSeconds(300),
                claims);
        OidcUser oidcUser = new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                idToken);
        OAuth2AuthenticationToken authToken = new OAuth2AuthenticationToken(
                oidcUser,
                oidcUser.getAuthorities(),
                "auth0");

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authToken);

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        return session;
    }
}
