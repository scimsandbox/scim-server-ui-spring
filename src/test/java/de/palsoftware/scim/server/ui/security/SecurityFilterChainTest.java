package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.ui.TestClientRegistrationConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
    "AUTH0_ISSUER_URI=https://test.auth0.com/"
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
        // workspace.js now depends on this file existing; a packaging slip would break every page's
        // 401 handling while leaving the rest of the suite green.
        mockMvc.perform(get("/js/api-client.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("global.apiFetch")));
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
}
