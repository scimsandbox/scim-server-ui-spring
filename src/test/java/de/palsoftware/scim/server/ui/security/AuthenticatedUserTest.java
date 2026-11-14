package de.palsoftware.scim.server.ui.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticatedUserTest {

    // ─── email & OIDC verification ──────────────────────────────────────

    @Test
    void email_nullAuth_throws() {
        assertThatThrownBy(() -> AuthenticatedUser.email(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Missing authentication");
    }

    @Test
    void email_oidcUser_verifiedEmail_returnsNormalizedEmail() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(true);
        when(oidcUser.getEmail()).thenReturn("  Email@Test.com  ");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.email(auth)).isEqualTo("email@test.com");
    }

    @Test
    void email_oidcUser_unverifiedEmail_throws() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(false);
        lenient().when(oidcUser.getEmail()).thenReturn("email@test.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThatThrownBy(() -> AuthenticatedUser.email(auth))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("verified email");
    }

    @Test
    void email_oidcUser_missingEmailVerifiedClaim_throws() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(null);
        when(oidcUser.getClaims()).thenReturn(Map.of("email", "email@test.com"));
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThatThrownBy(() -> AuthenticatedUser.email(auth))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("verified email");
    }

    @Test
    void resolveEmail_oidcUser_doesNotFallbackToPreferredUsernameOrUpn() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(true);
        when(oidcUser.getEmail()).thenReturn(null);
        lenient().when(oidcUser.getPreferredUsername()).thenReturn("preferred.user@example.com");
        lenient().when(oidcUser.getClaimAsString("upn")).thenReturn("user@domain.com");
        lenient().when(oidcUser.getClaimAsString("unique_name")).thenReturn("unique@domain.com");

        assertThat(AuthenticatedUser.resolveEmail(oidcUser)).isNull();
    }

    @Test
    void email_oidcUser_missingEmail_throws() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(true);
        when(oidcUser.getEmail()).thenReturn("   ");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThatThrownBy(() -> AuthenticatedUser.email(auth))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("verified email");
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
    void displayName_oidcUser_verifiedEmail_returnsEmail() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(true);
        when(oidcUser.getEmail()).thenReturn("display@test.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.displayName(auth)).isEqualTo("display@test.com");
    }

    @Test
    void displayName_oidcUser_noEmail_throwsInsteadOfUsingPreferredUsername() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmailVerified()).thenReturn(true);
        when(oidcUser.getEmail()).thenReturn(null);
        lenient().when(oidcUser.getPreferredUsername()).thenReturn("preferred@example.com");
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThatThrownBy(() -> AuthenticatedUser.displayName(auth))
                .isInstanceOf(IllegalStateException.class);
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
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
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
