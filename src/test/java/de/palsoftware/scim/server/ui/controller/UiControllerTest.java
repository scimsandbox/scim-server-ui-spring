package de.palsoftware.scim.server.ui.controller;

import org.junit.jupiter.api.Test;
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
}
