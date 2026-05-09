package de.palsoftware.scim.server.ui.repository;

import de.palsoftware.scim.server.ui.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.service.WorkspaceService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "AUTH0_CLIENT_ID=test-client",
        "AUTH0_CLIENT_SECRET=test-secret",
        "AUTH0_REDIRECT_URI=https://ui.scimsandbox.net/login/oauth2/code/auth0",
        "AUTH0_ISSUER_URI=https://test.auth0.com/",
        "app.stats.cache-ttl=PT5M"
})
class WorkspaceStatsCacheIntegrationTest extends PostgresIntegrationTestSupport {

    @MockitoBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockitoBean
    private WorkspaceRepository workspaceRepository;

    @MockitoBean
    private WorkspaceTokenRepository workspaceTokenRepository;

    @MockitoBean
    private EntityManager entityManager;

    @Autowired
    private WorkspaceService workspaceService;

    @Test
    void repeatedWorkspaceStatsRequests_useCacheWithinTtl() {
        UUID workspaceId = UUID.randomUUID();
        Workspace workspace = new Workspace();
        workspace.setId(workspaceId);
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));

        Query query = mock(Query.class);
        when(entityManager.createNativeQuery(anyString())).thenReturn(query);
        when(query.setParameter(eq("workspaceId"), eq(workspaceId))).thenReturn(query);
        when(query.getSingleResult()).thenReturn(new Object[] {
                1L, 2L, 3L, 4L,
                5L, 6L, 7L, 8L,
                9L, 10L, 11L, 12L,
                13L, 14L
        });

        WorkspaceDataStats first = workspaceService.getWorkspaceDataStats(workspaceId, "admin@example.com", true);
        WorkspaceDataStats second = workspaceService.getWorkspaceDataStats(workspaceId, "admin@example.com", true);

        assertThat(second).isEqualTo(first);
        verify(entityManager, times(1)).createNativeQuery(anyString());
        verify(query, times(1)).getSingleResult();
    }
}