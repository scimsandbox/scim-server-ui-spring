package de.palsoftware.scim.server.ui;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * A real registration repository for the full-context tests.
 *
 * <p>It cannot come from application.yml, because the issuer-uri there would send Spring off to fetch an
 * OIDC discovery document from a host that does not exist. A Mockito mock does not work either: it is not
 * {@link Iterable}, so SecurityConfig cannot enumerate it to derive the login URL, and OAuth2LoginConfigurer
 * would fall back to the generated /login page — making every redirect assertion pass against the wrong URL.
 */
@TestConfiguration
public class TestClientRegistrationConfig {

    public static final String REGISTRATION_ID = "auth0";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .clientId("test-client")
                .clientSecret("test-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/" + REGISTRATION_ID)
                .scope("openid", "profile", "email")
                .authorizationUri("https://test.auth0.com/authorize")
                .tokenUri("https://test.auth0.com/oauth/token")
                .jwkSetUri("https://test.auth0.com/.well-known/jwks.json")
                .issuerUri("https://test.auth0.com/")
                .userNameAttributeName("sub")
                .build());
    }
}
