package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.service.MgmtUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
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
    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        mgmtUserService = mock(MgmtUserService.class);
        securityConfig = new SecurityConfig(
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
    void mapAndProvisionOidcUser_rejectsUnverifiedEmail() {
        OidcUser unverified = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "email", "victim@example.com",
                "email_verified", false));

        assertThatThrownBy(() -> securityConfig.mapAndProvisionOidcUser(unverified))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_token"));

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_rejectsMissingEmailVerifiedClaim() {
        OidcUser missingVerified = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "email", "victim@example.com"));

        assertThatThrownBy(() -> securityConfig.mapAndProvisionOidcUser(missingVerified))
                .isInstanceOf(OAuth2AuthenticationException.class);

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_rejectsPreferredUsernameWithoutVerifiedEmail() {
        OidcUser preferredOnly = buildOidcUser(Map.of(
                "sub", "auth0|123",
                "preferred_username", "spoofed@example.com",
                "email_verified", true));

        assertThatThrownBy(() -> securityConfig.mapAndProvisionOidcUser(preferredOnly))
                .isInstanceOf(OAuth2AuthenticationException.class);

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void mapAndProvisionOidcUser_acceptsVerifiedEmailAndMapsRoles() {
        OidcUser verified = buildOidcUser(Map.of(
                "sub", "auth0|456",
                "email", "Admin.User@Example.com",
                "email_verified", true,
                ROLE_CLAIM, List.of("admin")));

        OidcUser mapped = securityConfig.mapAndProvisionOidcUser(verified);

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
        OidcUser mapped = securityConfig.mapAndProvisionOidcUser(stringTrue);
        assertThat(mapped).isNotNull();
        verify(mgmtUserService).provisionUser("string.verified@example.com");

        OidcUser stringFalse = buildOidcUser(Map.of(
                "sub", "auth0|790",
                "email", "string.unverified@example.com",
                "email_verified", "false"));
        assertThatThrownBy(() -> securityConfig.mapAndProvisionOidcUser(stringFalse))
                .isInstanceOf(OAuth2AuthenticationException.class);

        // Non-Boolean/non-String claim (e.g. integer 1) causes ClaimAccessor.getClaimAsBoolean to throw
        // IllegalArgumentException; mapAndProvisionOidcUser must fail closed with OAuth2AuthenticationException
        // instead of leaking an unhandled 500 error.
        OidcUser nonBooleanClaim = buildOidcUser(Map.of(
                "sub", "auth0|791",
                "email", "malformed.claim@example.com",
                "email_verified", 1));
        assertThatThrownBy(() -> securityConfig.mapAndProvisionOidcUser(nonBooleanClaim))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_token"));
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Map<String, Object> tokenClaims = new HashMap<>(claims);
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("token-value", now, now.plusSeconds(300), tokenClaims);
        return new DefaultOidcUser(List.of(), idToken);
    }
}
