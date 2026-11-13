package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.ui.TestClientRegistrationConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Renders both Thymeleaf templates for real. Guards the shared-asset wiring, Content-Security-Policy
 * headers, and absence of inline scripts or event handlers that would violate strict script-src 'self'.
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
    "AUTH0_ISSUER_URI=https://test.auth0.com/",
    // Trailing slash on purpose: UiController must normalize it so links never contain "//".
    "APP_WEBSITE_URL=https://website.example.test/"
})
class TemplateRenderingTest extends PostgresIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "admin-user", roles = {"ADMIN"})
    void indexPageLoadsSharedAssetsAndCompliesWithStrictCsp() throws Exception {
        MvcResult result = renderResult("/");
        assertStrictCspHeader(result);
        String html = result.getResponse().getContentAsString();
        assertSharedAssetsAndNoInlineScripts(html);
        assertThat(html).contains("/js/index.js");
        assertThat(html.indexOf("/js/api-client.js"))
                .as("api-client.js must be loaded before index.js, which depends on apiFetch")
                .isLessThan(html.indexOf("/js/index.js"));
    }

    @Test
    @WithMockUser(username = "admin-user", roles = {"ADMIN"})
    void workspacePageLoadsTheSharedClientBeforeItsOwnScriptAndCompliesWithStrictCsp() throws Exception {
        MvcResult result = renderResult("/workspaces/" + UUID.randomUUID());
        assertStrictCspHeader(result);
        String html = result.getResponse().getContentAsString();
        assertSharedAssetsAndNoInlineScripts(html);
        assertThat(html.indexOf("/js/api-client.js"))
                .as("api-client.js must be loaded before workspace.js, which depends on apiFetch")
                .isLessThan(html.indexOf("/js/workspace.js"));
    }

    private MvcResult renderResult(String path) throws Exception {
        return mockMvc.perform(get(path))
                .andExpect(status().isOk())
                .andReturn();
    }

    private static void assertStrictCspHeader(MvcResult result) {
        String csp = result.getResponse().getHeader("Content-Security-Policy");
        assertThat(csp)
                .isNotNull()
                .contains("script-src 'self'")
                .contains("object-src 'none'")
                .contains("base-uri 'self'")
                .contains("frame-ancestors 'none'")
                .contains("connect-src 'self' https://website.example.test");
        assertThat(csp)
                .as("script-src must not permit unsafe-inline")
                .doesNotContain("script-src 'self' 'unsafe-inline'");
    }

    private static void assertSharedAssetsAndNoInlineScripts(String html) {
        assertThat(html).contains("/js/api-client.js");
        assertThat(html).contains("/css/workspace.css");
        assertThat(html).contains("/js/dock-news.js");
        assertThat(html).contains("floating-side-btn-news");
        assertThat(html)
                .as("the news link and feed must be built from the configured website URL, without a doubled slash")
                .contains("href=\"https://website.example.test/#news\"")
                .contains("data-news-feed-url=\"https://website.example.test/news/index.json\"");
        assertThat(html).contains("id=\"sessionExpiredBanner\"");
        assertThat(html).contains("data-action=\"sign-in-again\"");
        assertThat(html)
                .as("apiFetch must not be redefined per page; it comes from the shared client")
                .doesNotContain("async function apiFetch");
        assertThat(html)
                .as("templates must not contain inline <script> blocks without src=")
                .doesNotContainPattern("(?i)<script(?![^>]*\\bsrc=)[^>]*>");
        assertThat(html)
                .as("templates must not contain inline event handler attributes")
                .doesNotContainPattern("(?i)\\son[a-z]+\\s*=");
        assertThat(html)
                .as("the CSRF token must be rendered into the page for apiFetch to find")
                .containsPattern("name=\"_csrf\" content=\"[^\"]+\"");
    }
}
