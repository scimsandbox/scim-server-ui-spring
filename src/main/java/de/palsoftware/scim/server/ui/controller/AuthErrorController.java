package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.security.AuthErrorReason;
import de.palsoftware.scim.server.ui.security.SecurityConfig;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthErrorController {

    @GetMapping(SecurityConfig.AUTH_ERROR_PATH)
    public String authError(@RequestParam(name = "reason", required = false) String reason, Model model) {
        AuthErrorReason error = AuthErrorReason.fromCode(reason);
        model.addAttribute("errorTitle", error.title());
        model.addAttribute("errorMessage", error.message());
        return "auth-error";
    }
}
