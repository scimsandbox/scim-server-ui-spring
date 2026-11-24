package de.palsoftware.scim.server.ui.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
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

    private static final String NORMALIZED_EMAIL = "email@test.com";

    // ─── email & OIDC resolution ────────────────────────────────────────

    @Test
    void email_nullAuth_throws() {
        assertThatThrownBy(() -> AuthenticatedUser.email(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Missing authentication");
    }

    @Test
    void email_oidcUser_validEmail_resolvesRegardlessOfEmailVerifiedClaim() {
        OidcUser verifiedTrue = buildOidcUser(Map.of(
                "sub", "auth0|1",
                "email", "  Email@Test.com  ",
                "email_verified", true));
        OidcUser verifiedFalse = buildOidcUser(Map.of(
                "sub", "auth0|2",
                "email", "  Email@Test.com  ",
                "email_verified", false));
        OidcUser verifiedOmitted = buildOidcUser(Map.of(
                "sub", "auth0|3",
                "email", "Email@Test.com"));

        assertThat(AuthenticatedUser.email(mockAuthWithPrincipal(verifiedTrue))).isEqualTo(NORMALIZED_EMAIL);
        assertThat(AuthenticatedUser.email(mockAuthWithPrincipal(verifiedFalse))).isEqualTo(NORMALIZED_EMAIL);
        assertThat(AuthenticatedUser.email(mockAuthWithPrincipal(verifiedOmitted))).isEqualTo(NORMALIZED_EMAIL);
        assertThat(AuthenticatedUser.resolveEmail(verifiedTrue)).isEqualTo(NORMALIZED_EMAIL);
        assertThat(AuthenticatedUser.resolveEmail(verifiedFalse)).isEqualTo(NORMALIZED_EMAIL);
        assertThat(AuthenticatedUser.resolveEmail(verifiedOmitted)).isEqualTo(NORMALIZED_EMAIL);
    }

    @Test
    void resolveEmail_nullOidcUser_returnsNull() {
        assertThat(AuthenticatedUser.resolveEmail((OidcUser) null)).isNull();
        assertThat(AuthenticatedUser.resolveEmail((Authentication) null)).isNull();
    }

    @Test
    void resolveEmail_oidcUser_doesNotFallbackToPreferredUsernameOrUpn() {
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmail()).thenReturn(null);
        lenient().when(oidcUser.getPreferredUsername()).thenReturn("preferred.user@example.com");
        lenient().when(oidcUser.getClaimAsString("upn")).thenReturn("user@domain.com");
        lenient().when(oidcUser.getClaimAsString("unique_name")).thenReturn("unique@domain.com");

        assertThat(AuthenticatedUser.resolveEmail(oidcUser)).isNull();
        assertThatThrownBy(() -> AuthenticatedUser.email(mockAuthWithPrincipal(oidcUser)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("valid email");
    }

    @Test
    void email_oidcUser_blankOrInvalidEmail_throws() {
        OidcUser blankEmail = buildOidcUser(Map.of("sub", "auth0|blank", "email", "   "));
        OidcUser invalidEmail = buildOidcUser(Map.of(
                "sub", "auth0|invalid",
                "email", "not-an-email",
                "preferred_username", "preferred@example.com"));

        assertThat(AuthenticatedUser.resolveEmail(blankEmail)).isNull();
        assertThat(AuthenticatedUser.resolveEmail(invalidEmail)).isNull();
        assertThatThrownBy(() -> AuthenticatedUser.email(mockAuthWithPrincipal(blankEmail)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("valid email");
        assertThatThrownBy(() -> AuthenticatedUser.email(mockAuthWithPrincipal(invalidEmail)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("valid email");
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
    void displayName_oidcUser_validEmail_returnsEmail() {
        OidcUser oidcUser = buildOidcUser(Map.of("sub", "auth0|display", "email", "display@test.com"));
        Authentication auth = mockAuthWithPrincipal(oidcUser);

        assertThat(AuthenticatedUser.displayName(auth)).isEqualTo("display@test.com");
    }

    @Test
    void displayName_oidcUser_noEmail_throwsInsteadOfUsingPreferredUsername() {
        OidcUser oidcUser = buildOidcUser(Map.of(
                "sub", "auth0|noemail",
                "preferred_username", "preferred@example.com"));
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

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("token-value", now, now.plusSeconds(300), claims);
        return new DefaultOidcUser(List.of(), idToken);
    }
}
