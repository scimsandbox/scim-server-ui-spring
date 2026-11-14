package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.service.MgmtUserService;
import de.palsoftware.scim.server.ui.utils.HttpUrlUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

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
        this.scimApiBaseUrl = HttpUrlUtils.normalizeHttpUrl(
                scimApiBaseUrl,
                "app.scim-api.base.url (APP_SCIM_API_BASE_URL) must be an absolute http(s) URL, e.g. https://api.scimsandbox.net");
        this.validatorUrl = HttpUrlUtils.normalizeHttpUrl(
                validatorUrl,
                "app.validator.url (APP_VALIDATOR_URL) must be an absolute http(s) URL, e.g. https://validator.scimsandbox.net");
        this.websiteUrl = HttpUrlUtils.normalizeHttpUrl(
                websiteUrl,
                "app.website.url (APP_WEBSITE_URL) must be an absolute http(s) URL, e.g. https://scimsandbox.net");
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
