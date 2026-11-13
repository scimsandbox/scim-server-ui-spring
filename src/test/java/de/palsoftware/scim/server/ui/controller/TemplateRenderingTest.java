package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import de.palsoftware.scim.server.ui.TestClientRegistrationConfig;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Renders both Thymeleaf templates for real. Guards the shared-asset wiring: apiFetch and the
 * session-expiry handling live in js/api-client.js, so a page that fails to load it silently loses
 * its 401 handling, and a broken th: expression would otherwise only surface at runtime.
 */
@Import(TestClientRegistrationConfig.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "spring.jpa.open-in-view=false",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret",
    "AUTH0_REDIRECT_URI=https://ui.scimsandbox.net/login/oauth2/code/auth0",
    "AUTH0_ISSUER_URI=https://test.auth0.com/"
})
class TemplateRenderingTest extends PostgresIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;


    @Test
    @WithMockUser(username = "admin-user", roles = {"ADMIN"})
    void indexPageLoadsTheSharedClientAndStylesheet() throws Exception {
        assertSharedAssets(render("/"));
    }

    @Test
    @WithMockUser(username = "admin-user", roles = {"ADMIN"})
    void workspacePageLoadsTheSharedClientBeforeItsOwnScript() throws Exception {
        String html = render("/workspaces/" + UUID.randomUUID());
        assertSharedAssets(html);
        assertThat(html.indexOf("/js/api-client.js"))
                .as("api-client.js must be loaded before workspace.js, which depends on apiFetch")
                .isLessThan(html.indexOf("/js/workspace.js"));
    }

    private String render(String path) throws Exception {
        return mockMvc.perform(get(path))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private static void assertSharedAssets(String html) {
        assertThat(html).contains("/js/api-client.js");
        assertThat(html).contains("/css/workspace.css");
        assertThat(html).contains("floating-side-btn-news");
        assertThat(html).contains("/#news");
        assertThat(html).contains("id=\"sessionExpiredBanner\"");
        assertThat(html).contains("signInAgain()");
        assertThat(html)
                .as("apiFetch must not be redefined per page; it comes from the shared client")
                .doesNotContain("async function apiFetch");
        // A real model binding, so this fails if the template stops rendering rather than merely
        // stops containing a literal. apiFetch reads this token to sign every mutating request.
        assertThat(html)
                .as("the CSRF token must be rendered into the page for apiFetch to find")
                .containsPattern("name=\"_csrf\" content=\"[^\"]+\"");
    }
}
