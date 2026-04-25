package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.model.WorkspaceToken;
import de.palsoftware.scim.server.ui.repository.WorkspaceDataStats;
import de.palsoftware.scim.server.ui.repository.WorkspaceRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceStatsRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.ui.security.TokenSecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional(readOnly = true)
public class WorkspaceService {

    private final WorkspaceRepository workspaceRepository;
    private final WorkspaceTokenRepository tokenRepository;
    private final WorkspaceStatsRepository workspaceStatsRepository;
    private final Duration defaultTokenValidity;

    public WorkspaceService(WorkspaceRepository workspaceRepository,
                             WorkspaceTokenRepository tokenRepository,
                             WorkspaceStatsRepository workspaceStatsRepository,
                             @Value("${app.token.default-validity}") Duration defaultTokenValidity) {
        this.workspaceRepository = workspaceRepository;
        this.tokenRepository = tokenRepository;
        this.workspaceStatsRepository = workspaceStatsRepository;
        this.defaultTokenValidity = defaultTokenValidity;
    }

    @Transactional
    public Workspace createWorkspace(String name, String description, String createdByUsername) {
        if (workspaceRepository.existsByNameAndCreatedByUsername(name, createdByUsername)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                "Workspace with name '" + name + "' already exists");
        }

        Workspace ws = new Workspace();
        ws.setName(name);
        ws.setDescription(description);
        ws.setCreatedByUsername(createdByUsername);
        return workspaceRepository.save(ws);
    }

    public List<Workspace> listWorkspaces(String actorUsername, boolean admin) {
        if (admin) {
            return workspaceRepository.findAllOrderByCreatedAtDesc();
        }
        return workspaceRepository.findByCreatedByUsernameOrderByCreatedAtDesc(actorUsername);
    }

    public Optional<Workspace> getWorkspace(UUID id, String actorUsername, boolean admin) {
        if (admin) {
            return workspaceRepository.findById(id);
        }
        return workspaceRepository.findByIdAndCreatedByUsername(id, actorUsername);
    }

    public Workspace requireWorkspaceAccess(UUID id, String actorUsername, boolean admin) {
        return getWorkspace(id, actorUsername, admin)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Workspace not found"));
    }

    public UUID requireWorkspaceId(String workspaceId, String actorUsername, boolean admin) {
        UUID wsId = UUID.fromString(workspaceId);
        requireWorkspaceAccess(wsId, actorUsername, admin);
        return wsId;
    }

    public WorkspaceDataStats getWorkspaceDataStats(UUID workspaceId, String actorUsername, boolean admin) {
        requireWorkspaceAccess(workspaceId, actorUsername, admin);
        return workspaceStatsRepository.fetchWorkspaceDataStats(workspaceId);
    }

    @Transactional
    public void deleteWorkspace(UUID id, String actorUsername, boolean admin) {
        Workspace workspace = requireWorkspaceAccess(id, actorUsername, admin);
        workspaceRepository.delete(workspace);
    }

    /**
     * Generate a new bearer token for a workspace.
     * Returns the raw token value (shown once to the user).
     */
    @Transactional
    public String generateToken(UUID workspaceId, String name, String description, String actorUsername, boolean admin) {
        Workspace ws = requireWorkspaceAccess(workspaceId, actorUsername, admin);

        String rawToken = generateSecureToken();
        String tokenHash = TokenSecurityUtil.sha256Hex(rawToken);

        WorkspaceToken token = new WorkspaceToken();
        token.setWorkspace(ws);
        token.setTokenHash(tokenHash);
        token.setName(name);
        token.setDescription(description);
        token.setExpiresAt(Instant.now().plus(defaultTokenValidity));
        tokenRepository.save(token);

        return rawToken;
    }

    public List<WorkspaceToken> listTokens(UUID workspaceId, String actorUsername, boolean admin) {
        requireWorkspaceAccess(workspaceId, actorUsername, admin);
        return tokenRepository.findByWorkspaceId(workspaceId);
    }

    @Transactional
    public void revokeToken(UUID workspaceId, UUID tokenId, String actorUsername, boolean admin) {
        requireWorkspaceAccess(workspaceId, actorUsername, admin);
        WorkspaceToken token = tokenRepository.findByIdAndWorkspaceId(tokenId, workspaceId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Token not found"));
        token.setRevoked(true);
        tokenRepository.save(token);
    }

    private String generateSecureToken() {
        return TokenSecurityUtil.generateSecureToken();
    }
}
