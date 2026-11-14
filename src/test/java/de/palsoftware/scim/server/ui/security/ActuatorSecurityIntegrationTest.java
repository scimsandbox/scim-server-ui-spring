package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.ui.TestClientRegistrationConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureObservability
@Import(TestClientRegistrationConfig.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "spring.jpa.open-in-view=false",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret",
    "AUTH0_REDIRECT_URI=https://ui.scimsandbox.net/login/oauth2/code/auth0",
    "AUTH0_ISSUER_URI=https://test.auth0.com/",
    "APP_WEBSITE_URL=https://website.example.test",
    "management.server.port=",
    "ACTUATOR_API_KEY=integration-actuator-secret"
})
class ActuatorSecurityIntegrationTest extends PostgresIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthEndpointHidesComponentsUntilAuthorizedWithApiKey() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").doesNotExist());

        mockMvc.perform(get("/actuator/health")
                        .header(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "integration-actuator-secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").exists());
    }

    @Test
    @WithMockUser(username = "signed-in-user@example.test", roles = {"USER", "ADMIN"})
    void healthEndpointDoesNotExposeComponentsToSignedInOidcUsersWithoutApiKey() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").doesNotExist());
    }

    @Test
    void actuatorApiKeyRequestDoesNotOverwriteLoggedInUsersSessionSecurityContext() throws Exception {
        Authentication userAuth = UsernamePasswordAuthenticationToken.authenticated(
                "owner@example.test",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContext sessionContext = SecurityContextHolder.createEmptyContext();
        sessionContext.setAuthentication(userAuth);

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, sessionContext);

        mockMvc.perform(get("/actuator/health")
                        .session(session)
                        .header(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "integration-actuator-secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components").exists());

        SecurityContext afterRequest = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(afterRequest).isSameAs(sessionContext);
        assertThat(afterRequest.getAuthentication()).isSameAs(userAuth);
        assertThat(afterRequest.getAuthentication().getName()).isEqualTo("owner@example.test");
    }

    @Test
    void nonHealthActuatorEndpointsRequireValidApiKey() throws Exception {
        mockMvc.perform(get("/actuator/prometheus"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/actuator/prometheus")
                        .header(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "wrong-secret"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/actuator/prometheus")
                        .header(ActuatorApiKeyAuthFilter.API_KEY_HEADER, "integration-actuator-secret"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/actuator/prometheus")
                        .header(ActuatorApiKeyAuthFilter.ALT_API_KEY_HEADER, "integration-actuator-secret"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/actuator/health")
                        .header(ActuatorApiKeyAuthFilter.ALT_API_KEY_HEADER, "integration-actuator-secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components").exists());
    }

    @Test
    void actuatorPathTraversalIsRejectedWithBadRequest() throws Exception {
        mockMvc.perform(get("/actuator/health/../prometheus"))
                .andExpect(status().isBadRequest());
    }
}
