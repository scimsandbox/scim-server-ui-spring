package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.model.ScimGroupMembership;
import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.model.ScimUserEmail;
import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.repository.ScimGroupRepository;
import de.palsoftware.scim.server.ui.repository.ScimUserRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceRepository;
import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.ui.model.MgmtUser;
import de.palsoftware.scim.server.ui.repository.MgmtUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "spring.jpa.open-in-view=false",
    "ACTUATOR_API_KEY=test-key",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret",
    "AUTH0_REDIRECT_URI=https://ui.scimsandbox.net/login/oauth2/code/auth0",
    "AUTH0_ISSUER_URI=https://test.auth0.com/"
})
class LazyLoadingIntegrationTest extends PostgresIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ScimUserRepository userRepository;

    @Autowired
    private ScimGroupRepository groupRepository;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private MgmtUserRepository mgmtUserRepository;

    @MockitoBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @Test
    @WithMockUser(username = "admin-user", roles = {"ADMIN"})
    void testListUsersAndGroups_generatesNoLazyInitializationException() throws Exception {
        // Create an admin user for workspace ownership and request context
        MgmtUser mgmtUser = new MgmtUser("admin@example.com", OffsetDateTime.now(ZoneOffset.UTC));
        mgmtUserRepository.save(mgmtUser);

        // Create workspace
        Workspace ws = new Workspace();
        ws.setName("test-ws-" + UUID.randomUUID());
        ws.setCreatedByUsername("admin-user");
        ws = workspaceRepository.save(ws);

        // Create a user with a lazy collection
        ScimUser user = new ScimUser();
        user.setWorkspace(ws);
        user.setUserName("lazy.test.user");
        user.setExternalId("ext-user-1");

        ScimUserEmail email = new ScimUserEmail();
        email.setValue("lazy@example.com");
        email.setType("work");
        user.getEmails().add(email);

        user = userRepository.saveAndFlush(user);

        // Create a group with a lazy collection
        ScimGroup group = new ScimGroup();
        group.setWorkspace(ws);
        group.setDisplayName("Lazy Test Group");
        group.setExternalId("ext-group-1");

        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberType("User");
        membership.setMemberValue(user.getId());
        membership.setDisplay("lazy.test.user");
        group.getMembers().add(membership);

        groupRepository.saveAndFlush(group);

        // Perform GET request for users that triggers mapper outside transaction.
        // It relies on ScimAdminService manually hydrating domains before return.
        mockMvc.perform(get("/api/workspaces/" + ws.getId() + "/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray())
                .andExpect(jsonPath("$.items[0].userName").value("lazy.test.user"))
                .andExpect(jsonPath("$.items[0].emails").isArray())
                .andExpect(jsonPath("$.items[0].emails[0].value").value("lazy@example.com"));

        // Perform GET request for groups that triggers mapper outside transaction.
        mockMvc.perform(get("/api/workspaces/" + ws.getId() + "/groups"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray())
                .andExpect(jsonPath("$.items[0].displayName").value("Lazy Test Group"))
                .andExpect(jsonPath("$.items[0].members").isArray())
                .andExpect(jsonPath("$.items[0].members[0].value").value(user.getId().toString()));
    }
}
