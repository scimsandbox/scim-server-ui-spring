package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.model.WorkspaceToken;
import de.palsoftware.scim.server.ui.repository.WorkspaceDataStats;
import de.palsoftware.scim.server.ui.repository.WorkspaceRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceStatsRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WorkspaceServiceTest {

    @Mock
    private WorkspaceRepository workspaceRepository;
    @Mock
    private WorkspaceTokenRepository tokenRepository;
    @Mock
    private WorkspaceStatsRepository workspaceStatsRepository;

    private WorkspaceService service;

    private static final Duration DEFAULT_TOKEN_VALIDITY = Duration.ofDays(30);

    private final UUID workspaceId = UUID.randomUUID();
    private Workspace workspace;

    @BeforeEach
    void setUp() {
        service = new WorkspaceService(workspaceRepository, tokenRepository,
                workspaceStatsRepository, DEFAULT_TOKEN_VALIDITY);
        workspace = new Workspace();
        workspace.setId(workspaceId);
        workspace.setName("Test WS");
        workspace.setCreatedByUsername("owner");
    }

    // ─── createWorkspace ────────────────────────────────────────────────

    @Test
    void createWorkspace_success() {
        when(workspaceRepository.existsByNameAndCreatedByUsername("WS", "owner")).thenReturn(false);
        when(workspaceRepository.save(any(Workspace.class))).thenAnswer(i -> {
            Workspace ws = i.getArgument(0);
            ws.setId(workspaceId);
            return ws;
        });

        Workspace result = service.createWorkspace("WS", "desc", "owner");

        assertThat(result.getName()).isEqualTo("WS");
        assertThat(result.getDescription()).isEqualTo("desc");
        verify(workspaceRepository).save(any(Workspace.class));
    }

    @Test
    void createWorkspace_duplicateNameForOwner_throwsConflict() {
        when(workspaceRepository.existsByNameAndCreatedByUsername("WS", "owner")).thenReturn(true);

        assertThatThrownBy(() -> service.createWorkspace("WS", "desc", "owner"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> {
                    assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(ex.getReason()).contains("Workspace with name 'WS' already exists");
                });
    }

    // ─── listWorkspaces ─────────────────────────────────────────────────

    @Test
    void listWorkspaces_admin_returnsAll() {
        when(workspaceRepository.findAllOrderByCreatedAtDesc()).thenReturn(List.of(workspace));

        List<Workspace> result = service.listWorkspaces("anyone", true);

        assertThat(result).hasSize(1);
    }

    @Test
    void listWorkspaces_nonAdmin_returnsOwned() {
        when(workspaceRepository.findByCreatedByUsernameOrderByCreatedAtDesc("owner"))
                .thenReturn(List.of(workspace));

        List<Workspace> result = service.listWorkspaces("owner", false);

        assertThat(result).hasSize(1);
    }

    // ─── getWorkspace ───────────────────────────────────────────────────

    @Test
    void getWorkspace_admin_found() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));

        Optional<Workspace> result = service.getWorkspace(workspaceId, "admin", true);

        assertThat(result).isPresent();
    }

    @Test
    void getWorkspace_nonAdmin_found() {
        when(workspaceRepository.findByIdAndCreatedByUsername(workspaceId, "owner"))
                .thenReturn(Optional.of(workspace));

        Optional<Workspace> result = service.getWorkspace(workspaceId, "owner", false);

        assertThat(result).isPresent();
    }

    @Test
    void getWorkspace_nonAdmin_notOwner_empty() {
        when(workspaceRepository.findByIdAndCreatedByUsername(workspaceId, "other"))
                .thenReturn(Optional.empty());

        Optional<Workspace> result = service.getWorkspace(workspaceId, "other", false);

        assertThat(result).isEmpty();
    }

    // ─── requireWorkspaceAccess ─────────────────────────────────────────

    @Test
    void requireWorkspaceAccess_notFound_throws() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.requireWorkspaceAccess(workspaceId, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    // ─── getWorkspaceDataStats ──────────────────────────────────────────

    @Test
    void getWorkspaceDataStats_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        WorkspaceDataStats stats = new WorkspaceDataStats(10, 5, 2, 100, 50, 30, 10, 5, 3, 2, 1, 0, 20, 4096);
        when(workspaceStatsRepository.fetchWorkspaceDataStats(workspaceId)).thenReturn(stats);

        WorkspaceDataStats result = service.getWorkspaceDataStats(workspaceId, "admin", true);

        assertThat(result.userCount()).isEqualTo(10);
    }

    // ─── deleteWorkspace ────────────────────────────────────────────────

    @Test
    void deleteWorkspace_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));

        service.deleteWorkspace(workspaceId, "admin", true);

        verify(workspaceRepository).delete(workspace);
    }

    // ─── generateToken ──────────────────────────────────────────────────

    @Test
    void generateToken_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(tokenRepository.save(any(WorkspaceToken.class))).thenAnswer(i -> i.getArgument(0));

        String token = service.generateToken(workspaceId, "tkn", "desc", "admin", true);

        assertThat(token).isNotBlank();
        verify(tokenRepository).save(any(WorkspaceToken.class));
    }

    @Test
    void generateToken_setsExpiresAt() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(tokenRepository.save(any(WorkspaceToken.class))).thenAnswer(i -> i.getArgument(0));

        Instant before = Instant.now();
        service.generateToken(workspaceId, "tkn", "desc", "admin", true);
        Instant after = Instant.now();

        ArgumentCaptor<WorkspaceToken> captor = ArgumentCaptor.forClass(WorkspaceToken.class);
        verify(tokenRepository).save(captor.capture());

        WorkspaceToken saved = captor.getValue();
        assertThat(saved.getExpiresAt()).isNotNull();
        Instant expectedMin = before.plus(DEFAULT_TOKEN_VALIDITY);
        Instant expectedMax = after.plus(DEFAULT_TOKEN_VALIDITY);
        assertThat(saved.getExpiresAt()).isBetween(expectedMin, expectedMax);
    }

    @Test
    void generateToken_expiresAtIsApproximately30DaysFromNow() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(tokenRepository.save(any(WorkspaceToken.class))).thenAnswer(i -> i.getArgument(0));

        service.generateToken(workspaceId, "tkn", "desc", "admin", true);

        ArgumentCaptor<WorkspaceToken> captor = ArgumentCaptor.forClass(WorkspaceToken.class);
        verify(tokenRepository).save(captor.capture());

        WorkspaceToken saved = captor.getValue();
        assertThat(saved.getExpiresAt()).isCloseTo(
                Instant.now().plus(30, ChronoUnit.DAYS), within(5, ChronoUnit.SECONDS));
    }

    // ─── listTokens ─────────────────────────────────────────────────────

    @Test
    void listTokens_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(tokenRepository.findByWorkspaceId(workspaceId)).thenReturn(List.of(new WorkspaceToken()));

        List<WorkspaceToken> result = service.listTokens(workspaceId, "admin", true);

        assertThat(result).hasSize(1);
    }

    // ─── revokeToken ────────────────────────────────────────────────────

    @Test
    void revokeToken_success() {
        UUID tokenId = UUID.randomUUID();
        WorkspaceToken token = new WorkspaceToken();
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(tokenRepository.findByIdAndWorkspaceId(tokenId, workspaceId)).thenReturn(Optional.of(token));
        when(tokenRepository.save(any(WorkspaceToken.class))).thenAnswer(i -> i.getArgument(0));

        service.revokeToken(workspaceId, tokenId, "admin", true);

        assertThat(token.isRevoked()).isTrue();
    }

    @Test
    void revokeToken_notFound_throws() {
        UUID tokenId = UUID.randomUUID();
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(tokenRepository.findByIdAndWorkspaceId(tokenId, workspaceId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.revokeToken(workspaceId, tokenId, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

}
