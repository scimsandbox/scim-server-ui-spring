package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.service.MgmtUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
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
    void mapAndProvisionOidcUser_provisionsNormalizedEmailRegardlessOfEmailVerifiedClaim() {
        OidcUser verifiedTrue = buildOidcUser(Map.of(
                "sub", "auth0|1",
                "email", "Admin.User@Example.com",
                "email_verified", true,
                ROLE_CLAIM, List.of("admin")));
        OidcUser verifiedFalse = buildOidcUser(Map.of(
                "sub", "auth0|2",
                "email", "Unverified.User@Example.com",
                "email_verified", false,
                ROLE_CLAIM, List.of("user")));
        OidcUser verifiedOmitted = buildOidcUser(Map.of(
                "sub", "auth0|3",
                "email", "Enterprise.User@Example.com"));

        OidcUser mappedAdmin = securityConfig.mapAndProvisionOidcUser(verifiedTrue);
        OidcUser mappedUnverified = securityConfig.mapAndProvisionOidcUser(verifiedFalse);
        OidcUser mappedEnterprise = securityConfig.mapAndProvisionOidcUser(verifiedOmitted);

        verify(mgmtUserService).provisionUser("admin.user@example.com");
        verify(mgmtUserService).provisionUser("unverified.user@example.com");
        verify(mgmtUserService).provisionUser("enterprise.user@example.com");
        assertThat(mappedAdmin.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER", "ROLE_ADMIN");
        assertThat(mappedUnverified.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
        assertThat(mappedEnterprise.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
    }

    @Test
    void mapAndProvisionOidcUser_rejectsNullMissingOrInvalidEmailWithInvalidToken() {
        assertInvalidToken(null);
        assertInvalidToken(buildOidcUser(Map.of(
                "sub", "auth0|preferred",
                "preferred_username", "spoofed@example.com")));
        assertInvalidToken(buildOidcUser(Map.of(
                "sub", "auth0|blank",
                "email", "   ")));
        assertInvalidToken(buildOidcUser(Map.of(
                "sub", "auth0|invalid",
                "email", "not-an-email")));

        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void oauth2FailureHandler_redirectsToAuthErrorWithAllowlistedOrDefaultReason() throws Exception {
        assertFailureRedirect(
                new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, "denied\r\nforged", null)),
                "/auth-error?reason=access_denied");
        assertFailureRedirect(
                new OAuth2AuthenticationException(new OAuth2Error("authorization_request_not_found")),
                "/auth-error?reason=authorization_request_not_found");
        assertFailureRedirect(
                new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN)),
                "/auth-error?reason=invalid_token");
        assertFailureRedirect(
                new OAuth2AuthenticationException(new OAuth2Error("weird_unknown")),
                "/auth-error?reason=authentication_failed");
        assertFailureRedirect(
                new BadCredentialsException("bad\nline"),
                "/auth-error?reason=authentication_failed");

        MockHttpServletRequest contextReq = new MockHttpServletRequest();
        contextReq.setContextPath("/app");
        MockHttpServletResponse contextRes = new MockHttpServletResponse();
        securityConfig.oauth2FailureHandler().onAuthenticationFailure(
                contextReq,
                contextRes,
                new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED)));
        assertThat(contextRes.getRedirectedUrl()).isEqualTo("/app/auth-error?reason=access_denied");
    }

    @Test
    void oidcLoginUrlAndAuthorizationRequestResolver_derivePathAndAllowlistPromptLogin() {
        ClientRegistration okta = buildRegistration("okta");
        ClientRegistrationRepository singleRepo = new InMemoryClientRegistrationRepository(okta);
        assertThat(SecurityConfig.oidcLoginUrl(singleRepo)).isEqualTo("/oauth2/authorization/okta");

        ClientRegistrationRepository multiRepo = new InMemoryClientRegistrationRepository(okta, buildRegistration("entra"));
        assertThatThrownBy(() -> SecurityConfig.oidcLoginUrl(multiRepo))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SecurityConfig.oidcLoginUrl(mock(ClientRegistrationRepository.class)))
                .isInstanceOf(IllegalStateException.class);

        OAuth2AuthorizationRequestResolver resolver = securityConfig.authorizationRequestResolver(singleRepo);

        MockHttpServletRequest promptLoginReq = new MockHttpServletRequest("GET", "/oauth2/authorization/okta");
        promptLoginReq.setServletPath("/oauth2/authorization/okta");
        promptLoginReq.setParameter("prompt", "login");
        OAuth2AuthorizationRequest withPrompt = resolver.resolve(promptLoginReq);
        assertThat(withPrompt).isNotNull();
        assertThat(withPrompt.getAdditionalParameters()).containsEntry("prompt", "login");

        OAuth2AuthorizationRequest withPromptById = resolver.resolve(promptLoginReq, "okta");
        assertThat(withPromptById).isNotNull();
        assertThat(withPromptById.getAdditionalParameters()).containsEntry("prompt", "login");

        MockHttpServletRequest otherPromptReq = new MockHttpServletRequest("GET", "/oauth2/authorization/okta");
        otherPromptReq.setServletPath("/oauth2/authorization/okta");
        otherPromptReq.setParameter("prompt", "none");
        OAuth2AuthorizationRequest withoutPrompt = resolver.resolve(otherPromptReq);
        assertThat(withoutPrompt).isNotNull();
        assertThat(withoutPrompt.getAdditionalParameters()).doesNotContainKey("prompt");

        MockHttpServletRequest nonAuthReq = new MockHttpServletRequest("GET", "/other");
        nonAuthReq.setServletPath("/other");
        assertThat(resolver.resolve(nonAuthReq)).isNull();
    }

    private static ClientRegistration buildRegistration(String id) {
        return ClientRegistration.withRegistrationId(id)
                .clientId("client-id")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/" + id)
                .authorizationUri("https://idp.example.test/authorize")
                .tokenUri("https://idp.example.test/token")
                .build();
    }

    private void assertInvalidToken(OidcUser oidcUser) {
        assertThatThrownBy(() -> securityConfig.mapAndProvisionOidcUser(oidcUser))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
    }

    private void assertFailureRedirect(AuthenticationException ex,
                                       String expectedUrl) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        securityConfig.oauth2FailureHandler().onAuthenticationFailure(req, res, ex);
        assertThat(res.getRedirectedUrl()).isEqualTo(expectedUrl);
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Map<String, Object> tokenClaims = new HashMap<>(claims);
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("token-value", now, now.plusSeconds(300), tokenClaims);
        return new DefaultOidcUser(List.of(), idToken);
    }
}
