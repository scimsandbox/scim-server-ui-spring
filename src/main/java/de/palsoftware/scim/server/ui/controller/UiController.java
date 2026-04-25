package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.service.MgmtUserService;
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

    public UiController(MgmtUserService mgmtUserService,
            @Value("${app.scim-api.base.url}") String scimApiBaseUrl,
            @Value("${app.validator.url}") String validatorUrl) {
        this.mgmtUserService = mgmtUserService;
        this.scimApiBaseUrl = scimApiBaseUrl;
        this.validatorUrl = validatorUrl;
    }

    @GetMapping("/")
    public String index(Model model, Authentication authentication) {
        model.addAttribute("currentUser", resolveDisplayName(authentication));
        model.addAttribute("currentUserRole", AuthenticatedUser.isAdmin(authentication) ? "Admin" : "User");
        model.addAttribute("validatorUrl", validatorUrl);
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
    }

    private String resolveDisplayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        return mgmtUserService.resolveDisplayName(AuthenticatedUser.email(authentication))
                .orElseGet(() -> AuthenticatedUser.displayName(authentication));
    }
}
