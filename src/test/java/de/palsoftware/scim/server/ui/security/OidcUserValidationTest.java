package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.service.MgmtUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class OidcUserValidationTest {

    private static final String ROLE_CLAIM = "https://scimplayground.dev/roles";

    private MgmtUserService mgmtUserService;
    private SecurityConfig strictConfig;
    private SecurityConfig defaultConfig;

    @BeforeEach
    void setUp() {
        mgmtUserService = mock(MgmtUserService.class);
        strictConfig = new SecurityConfig(
                "admin",
                "user",
                ROLE_CLAIM,
                true,
                "",
                "9090",
                "8080",
                "https://website.example.test",
                mgmtUserService);
        defaultConfig = new SecurityConfig(
                "admin",
                "user",
                ROLE_CLAIM,
                "",
                "9090",
                "8080",
                "https://website.example.test",
                mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_whenRequireVerifiedEmailFalse_acceptsUnverifiedEmail() {
        OidcUser unverified = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "email", "Unverified.User@Example.com",
                "email_verified", false,
                ROLE_CLAIM, List.of("user")));

        OidcUser mapped = defaultConfig.mapAndProvisionOidcUser(unverified);

        verify(mgmtUserService).provisionUser("unverified.user@example.com");
        assertThat(mapped.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
    }

    @Test
    void mapAndProvisionOidcUser_whenRequireVerifiedEmailFalse_stillRejectsNullOrMissingEmail() {
        assertThatThrownBy(() -> defaultConfig.mapAndProvisionOidcUser(null))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_token"));

        OidcUser preferredOnly = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "preferred_username", "spoofed@example.com"));
        assertThatThrownBy(() -> defaultConfig.mapAndProvisionOidcUser(preferredOnly))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_token"));

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_whenRequireVerifiedEmailTrue_rejectsUnverifiedEmail() {
        OidcUser unverified = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "email", "victim@example.com",
                "email_verified", false));

        assertThatThrownBy(() -> strictConfig.mapAndProvisionOidcUser(unverified))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("unverified_email"));

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_whenRequireVerifiedEmailTrue_rejectsMissingEmailVerifiedClaim() {
        OidcUser missingVerified = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "email", "victim@example.com"));

        assertThatThrownBy(() -> strictConfig.mapAndProvisionOidcUser(missingVerified))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("unverified_email"));

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_rejectsPreferredUsernameWithoutVerifiedEmail() {
        OidcUser preferredOnly = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "preferred_username", "spoofed@example.com",
                "email_verified", true));

        assertThatThrownBy(() -> strictConfig.mapAndProvisionOidcUser(preferredOnly))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_token"));

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_acceptsVerifiedEmailAndMapsRoles() {
        OidcUser verified = buildOidcUser(Map.of(
                "sub", "auth0|456",
                "email", "Admin.User@Example.com",
                "email_verified", true,
                ROLE_CLAIM, List.of("admin")));

        OidcUser mapped = strictConfig.mapAndProvisionOidcUser(verified);

        verify(mgmtUserService).provisionUser("admin.user@example.com");
        assertThat(mapped.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void mapAndProvisionOidcUser_handlesStringAndNonBooleanEmailVerifiedClaimsCleanly() {
        OidcUser stringTrue = buildOidcUser(Map.of(
                "sub", "auth0|789",
                "email", "string.verified@example.com",
                "email_verified", "true"));
        OidcUser mapped = strictConfig.mapAndProvisionOidcUser(stringTrue);
        assertThat(mapped).isNotNull();
        verify(mgmtUserService).provisionUser("string.verified@example.com");

        OidcUser stringFalse = buildOidcUser(Map.of(
                "sub", "auth0|790",
                "email", "string.unverified@example.com",
                "email_verified", "false"));
        assertThatThrownBy(() -> strictConfig.mapAndProvisionOidcUser(stringFalse))
                .isInstanceOf(OAuth2AuthenticationException.class);

        OidcUser nonBooleanClaim = buildOidcUser(Map.of(
                "sub", "auth0|791",
                "email", "malformed.claim@example.com",
                "email_verified", 1));
        assertThatThrownBy(() -> strictConfig.mapAndProvisionOidcUser(nonBooleanClaim))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("unverified_email"));
    }

    @Test
    void oauth2FailureHandler_redirectsToAuthErrorWithAllowlistedReason() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();

        defaultConfig.oauth2FailureHandler().onAuthenticationFailure(
                req,
                res,
                new OAuth2AuthenticationException(new OAuth2Error("unverified_email", "verify", null)));

        assertThat(res.getRedirectedUrl()).isEqualTo("/auth-error?reason=unverified_email");
        assertThat(SecurityConfig.resolveAuthErrorReason(
                new OAuth2AuthenticationException(new OAuth2Error("access_denied")))).isEqualTo("access_denied");
        assertThat(SecurityConfig.resolveAuthErrorReason(
                new OAuth2AuthenticationException(new OAuth2Error("authorization_request_not_found"))))
                .isEqualTo("authorization_request_not_found");
        assertThat(SecurityConfig.resolveAuthErrorReason(
                new OAuth2AuthenticationException(new OAuth2Error("invalid_token")))).isEqualTo("invalid_token");
        assertThat(SecurityConfig.resolveAuthErrorReason(
                new OAuth2AuthenticationException(new OAuth2Error("weird_unknown")))).isEqualTo("authentication_failed");
        assertThat(SecurityConfig.resolveAuthErrorReason(new BadCredentialsException("bad")))
                .isEqualTo("authentication_failed");
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Map<String, Object> tokenClaims = new HashMap<>(claims);
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("token-value", now, now.plusSeconds(300), tokenClaims);
        return new DefaultOidcUser(List.of(), idToken);
    }
}
