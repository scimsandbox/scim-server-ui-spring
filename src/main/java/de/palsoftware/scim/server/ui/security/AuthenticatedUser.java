package de.palsoftware.scim.server.ui.security;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Locale;

public final class AuthenticatedUser {

    private AuthenticatedUser() {
    }

    public static String email(Authentication authentication) {
        if (authentication == null) {
            throw new InvalidAuthenticatedPrincipalException("Missing authentication");
        }
        String resolved = resolveEmail(authentication);
        if (resolved != null) {
            return resolved;
        }
        if (authentication.getPrincipal() instanceof OidcUser) {
            throw new InvalidAuthenticatedPrincipalException("Authenticated principal is missing a valid email address");
        }
        throw new InvalidAuthenticatedPrincipalException("Unable to resolve authenticated email");
    }

    public static String resolveEmail(Authentication authentication) {
        return resolveEmail(authentication, false);
    }

    public static String resolveEmail(Authentication authentication, boolean requireVerifiedEmail) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            return resolveEmail(oidcUser, requireVerifiedEmail);
        }
        String fallback = authentication.getName();
        return (fallback == null || fallback.isBlank()) ? null : fallback;
    }

    public static String displayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        return email(authentication);
    }

    public static boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isEmailVerified(OidcUser oidcUser) {
        if (oidcUser == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(oidcUser.getEmailVerified());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public static String resolveEmail(OidcUser oidcUser) {
        return resolveEmail(oidcUser, false);
    }

    public static String resolveEmail(OidcUser oidcUser, boolean requireVerifiedEmail) {
        if (oidcUser == null) {
            return null;
        }
        if (requireVerifiedEmail && !isEmailVerified(oidcUser)) {
            return null;
        }
        return normalizeEmail(oidcUser.getEmail());
    }

    public static String normalizeEmail(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty() || !normalized.contains("@")) {
            return null;
        }
        return normalized;
    }
}
