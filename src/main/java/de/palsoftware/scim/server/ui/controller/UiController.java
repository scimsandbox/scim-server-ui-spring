package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.service.MgmtUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Server-side rendered management UI using Thymeleaf.
 */
@Controller
public class UiController {

    private final MgmtUserService mgmtUserService;
    private final String scimApiBaseUrl;
    private final String validatorUrl;
    private final String websiteUrl;

    public UiController(MgmtUserService mgmtUserService,
            @Value("${app.scim-api.base.url}") String scimApiBaseUrl,
            @Value("${app.validator.url}") String validatorUrl,
            @Value("${app.website.url}") String websiteUrl) {
        this.mgmtUserService = mgmtUserService;
        this.scimApiBaseUrl = scimApiBaseUrl;
        this.validatorUrl = normalizeHttpUrl(
                validatorUrl,
                "app.validator.url (APP_VALIDATOR_URL) must be an absolute http(s) URL, e.g. https://validator.scimsandbox.net");
        this.websiteUrl = normalizeHttpUrl(
                websiteUrl,
                "app.website.url (APP_WEBSITE_URL) must be an absolute http(s) URL, e.g. https://scimsandbox.net");
    }

    /**
     * External URLs rendered into templates are validated as absolute http(s) URLs with a host,
     * and trailing slashes are stripped to avoid doubled slashes when appending fixed paths.
     */
    private static String normalizeHttpUrl(String rawUrl, String errorMessage) {
        String normalized = rawUrl == null ? "" : rawUrl.trim();
        int end = normalized.length();
        while (end > 0 && normalized.charAt(end - 1) == '/') {
            end--;
        }
        normalized = normalized.substring(0, end);
        try {
            URI uri = new URI(normalized);
            String scheme = uri.getScheme();
            boolean http = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
            if (http && uri.getHost() != null) {
                return normalized;
            }
        } catch (URISyntaxException ex) {
            // fall through to the descriptive error below
        }
        throw new IllegalStateException(errorMessage);
    }

    @GetMapping("/")
    public String index(Model model, Authentication authentication) {
        model.addAttribute("currentUser", resolveDisplayName(authentication));
        model.addAttribute("currentUserRole", AuthenticatedUser.isAdmin(authentication) ? "Admin" : "User");
        model.addAttribute("validatorUrl", validatorUrl);
        model.addAttribute("websiteUrl", websiteUrl);
        return "index";
    }

    @GetMapping("/workspaces/{workspaceId}")
    public String workspaceDetail(@PathVariable String workspaceId, Model model, Authentication authentication) {
        populateWorkspaceModel(model, authentication);
        return "workspace";
    }


    private void populateWorkspaceModel(Model model, Authentication authentication) {
        model.addAttribute("currentUser", resolveDisplayName(authentication));
        model.addAttribute("currentUserRole", AuthenticatedUser.isAdmin(authentication) ? "Admin" : "User");
        model.addAttribute("scimApiBaseUrl", scimApiBaseUrl);
        model.addAttribute("validatorUrl", validatorUrl);
        model.addAttribute("websiteUrl", websiteUrl);
    }

    private String resolveDisplayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        return mgmtUserService.resolveDisplayName(AuthenticatedUser.email(authentication))
                .orElseGet(() -> AuthenticatedUser.displayName(authentication));
    }
}
