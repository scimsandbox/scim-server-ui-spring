package de.palsoftware.scim.server.ui.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticatedUserTest {

    // ─── email ──────────────────────────────────────────────────────────

    @Test
    void email_nullAuth_throws() {
        assertThatThrownBy(() -> AuthenticatedUser.email(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Missing authentication");
    }

    @Test
    void email_oidcUser_preferredUsernameEmail() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmail()).thenReturn(null);
        when(oidcUser.getClaimAsString("upn")).thenReturn(null);
        when(oidcUser.getClaimAsString("unique_name")).thenReturn(null);
        when(oidcUser.getPreferredUsername()).thenReturn("Preferred.User@example.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.email(auth)).isEqualTo("preferred.user@example.com");
    }

    @Test
    void email_oidcUser_upnFallback() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getPreferredUsername()).thenReturn(null);
        when(oidcUser.getClaimAsString("upn")).thenReturn("user@domain.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.email(auth)).isEqualTo("user@domain.com");
    }

    @Test
    void email_oidcUser_emailFallback() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getPreferredUsername()).thenReturn(null);
        when(oidcUser.getClaimAsString("upn")).thenReturn(null);
        when(oidcUser.getClaimAsString("unique_name")).thenReturn(null);
        when(oidcUser.getEmail()).thenReturn("email@test.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.email(auth)).isEqualTo("email@test.com");
    }

    @Test
    void email_oidcUser_missingEmail_throws() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getPreferredUsername()).thenReturn(null);
        when(oidcUser.getClaimAsString("upn")).thenReturn(null);
        when(oidcUser.getClaimAsString("unique_name")).thenReturn(null);
        when(oidcUser.getEmail()).thenReturn(null);
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThatThrownBy(() -> AuthenticatedUser.email(auth))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("missing an email");
    }

    @Test
    void email_nonOidc_fallsBackToName() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("not-oidc");
        when(auth.getName()).thenReturn("fallback-name");

        assertThat(AuthenticatedUser.email(auth)).isEqualTo("fallback-name");
    }

    @Test
    void email_noIdentifier_throws() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("not-oidc");
        when(auth.getName()).thenReturn(null);

        assertThatThrownBy(() -> AuthenticatedUser.email(auth))
                .isInstanceOf(IllegalStateException.class);
    }

    // ─── displayName ────────────────────────────────────────────────────

    @Test
    void displayName_null_returnsNull() {
        assertThat(AuthenticatedUser.displayName(null)).isNull();
    }

    @Test
    void displayName_oidcUser_returnsEmail() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmail()).thenReturn("display@test.com");
        when(oidcUser.getClaimAsString("upn")).thenReturn(null);
        when(oidcUser.getClaimAsString("unique_name")).thenReturn(null);
        when(oidcUser.getPreferredUsername()).thenReturn("preferred@example.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.displayName(auth)).isEqualTo("display@test.com");
    }

    @Test
    void displayName_oidcUser_noEmail_usesPreferredUsernameEmail() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmail()).thenReturn(null);
        when(oidcUser.getClaimAsString("upn")).thenReturn(null);
        when(oidcUser.getClaimAsString("unique_name")).thenReturn(null);
        when(oidcUser.getPreferredUsername()).thenReturn("preferred@example.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.displayName(auth)).isEqualTo("preferred@example.com");
    }

    // ─── isAdmin ────────────────────────────────────────────────────────

    @Test
    void isAdmin_null_returnsFalse() {
        assertThat(AuthenticatedUser.isAdmin(null)).isFalse();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    void isAdmin_withAdminRole_returnsTrue() {
        Authentication auth = mock(Authentication.class);
        Collection<GrantedAuthority>  authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        when(auth.getAuthorities()).thenReturn((Collection) authorities);

        assertThat(AuthenticatedUser.isAdmin(auth)).isTrue();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    void isAdmin_withoutAdminRole_returnsFalse() {
        Authentication auth = mock(Authentication.class);
        Collection<GrantedAuthority> authorities = List.<GrantedAuthority>of(new SimpleGrantedAuthority("ROLE_USER"));
        when(auth.getAuthorities()).thenReturn((Collection) authorities);

        assertThat(AuthenticatedUser.isAdmin(auth)).isFalse();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    void isAdmin_noAuthorities_returnsFalse() {
        Authentication auth = mock(Authentication.class);
        Collection<GrantedAuthority> authorities = Collections.<GrantedAuthority>emptyList();
        when(auth.getAuthorities()).thenReturn((Collection) authorities);

        assertThat(AuthenticatedUser.isAdmin(auth)).isFalse();
    }

    // ─── helpers ────────────────────────────────────────────────────────

    private Authentication mockAuthWithPrincipal(Object principal) {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(principal);
        return auth;
    }
}
