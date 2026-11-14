package de.palsoftware.scim.server.ui.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The website URL is required configuration: it feeds the What's New link and feed, so a blank value
 * must fail startup instead of rendering a relative link back to this app.
 */
class UiControllerTest {

    private static UiController controller(String websiteUrl) {
        return new UiController(null, "https://api.example.test", "https://val.example.test", websiteUrl);
    }

    @Test
    void stripsTrailingSlashesFromTheWebsiteUrl() {
        Model model = new ConcurrentModel();

        controller(" https://website.example.test// ").index(model, null);

        assertThat(model.getAttribute("websiteUrl")).isEqualTo("https://website.example.test");
    }

    @Test
    void rejectsMissingWebsiteUrl() {
        assertThatThrownBy(() -> controller(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.website.url");
    }

    @Test
    void rejectsBlankWebsiteUrl() {
        assertThatThrownBy(() -> controller("  /  "))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.website.url");
    }

    @ParameterizedTest
    @ValueSource(strings = {" https:// ", "https:", "scimsandbox.net", "//scimsandbox.net", "ftp://scimsandbox.net",
            "javascript:alert(1)", "https://sci msandbox.net"})
    void rejectsValuesThatAreNotAnAbsoluteHttpUrlWithAHost(String value) {
        assertThatThrownBy(() -> controller(value))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("absolute http(s) URL");
    }

    @Test
    void acceptsHttpUrlsWithPortAndPath() {
        Model model = new ConcurrentModel();

        controller("http://localhost:8099/site/").index(model, null);

        assertThat(model.getAttribute("websiteUrl")).isEqualTo("http://localhost:8099/site");
    }

    @Test
    void rejectsNonHttpValidatorUrlAndStripsTrailingSlash() {
        assertThatThrownBy(() -> new UiController(
                null, "https://api.example.test", "javascript:alert(1)", "https://website.example.test"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.validator.url");

        Model model = new ConcurrentModel();
        new UiController(null, "https://api.example.test///", "https://val.example.test///", "https://website.example.test")
                .workspaceDetail("ws-1", model, null);
        assertThat(model.getAttribute("validatorUrl")).isEqualTo("https://val.example.test");
        assertThat(model.getAttribute("scimApiBaseUrl")).isEqualTo("https://api.example.test");

        assertThatThrownBy(() -> new UiController(
                null, "javascript:alert(1)", "https://val.example.test", "https://website.example.test"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.scim-api.base.url");
    }
}
