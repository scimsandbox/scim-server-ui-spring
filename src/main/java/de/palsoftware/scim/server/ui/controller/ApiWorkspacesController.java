package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.model.WorkspaceToken;
import de.palsoftware.scim.server.ui.repository.WorkspaceDataStats;
import de.palsoftware.scim.server.ui.dto.GenerateDataRequest;
import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.service.DataGeneratorService;
import de.palsoftware.scim.server.ui.service.WorkspaceService;
import de.palsoftware.scim.server.ui.utils.WorkspaceResponseMapper;
import de.palsoftware.scim.server.ui.repository.MgmtUserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.core.Authentication;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class ApiWorkspacesController {

        private static final String KEY_NAME = "name";
        private static final String KEY_DESCRIPTION = "description";

        private final WorkspaceService workspaceService;
        private final DataGeneratorService workspaceDataGeneratorService;
        private final MgmtUserRepository mgmtUserRepository;

        public ApiWorkspacesController(WorkspaceService workspaceService,
                        DataGeneratorService workspaceDataGeneratorService,
                        MgmtUserRepository mgmtUserRepository) {
                this.workspaceService = workspaceService;
                this.workspaceDataGeneratorService = workspaceDataGeneratorService;
                this.mgmtUserRepository = mgmtUserRepository;

        }

        @PostMapping("/workspaces")
        public ResponseEntity<Map<String, Object>> createWorkspace(@RequestBody Map<String, String> body,
                        Authentication authentication) {
                String name = body.get(KEY_NAME);
                if (name == null || name.isBlank()) {
                        return ResponseEntity.badRequest().body(Map.of("error", "name is required"));
                }
                String description = body.get(KEY_DESCRIPTION);
                Workspace workspace = workspaceService.createWorkspace(
                                name,
                                description,
                                AuthenticatedUser.email(authentication));
                return ResponseEntity.status(201)
                                .body(WorkspaceResponseMapper.workspaceToMap(workspace, mgmtUserRepository));
        }

        @GetMapping("/workspaces")
        public ResponseEntity<List<Map<String, Object>>> listWorkspaces(Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                List<Workspace> workspaces = workspaceService.listWorkspaces(actorEmail, admin);
                return ResponseEntity.ok(WorkspaceResponseMapper.workspaceListToMaps(workspaces, mgmtUserRepository));
        }

        @GetMapping("/workspaces/{workspaceId}")
        public ResponseEntity<Map<String, Object>> getWorkspace(@PathVariable String workspaceId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                UUID wsId = UUID.fromString(workspaceId);
                return workspaceService.getWorkspace(wsId, actorEmail, admin)
                                .map(workspace -> {
                                        WorkspaceDataStats stats = workspaceService.getWorkspaceDataStats(
                                                        wsId,
                                                        actorEmail,
                                                        admin);
                                        return ResponseEntity.ok(
                                                        WorkspaceResponseMapper.workspaceDetailToMap(workspace, stats,
                                                                        mgmtUserRepository));
                                })
                                .orElse(ResponseEntity.notFound().build());
        }

        @GetMapping("/workspaces/{workspaceId}/stats")
        public ResponseEntity<Map<String, Object>> getWorkspaceStats(@PathVariable String workspaceId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                WorkspaceDataStats stats = workspaceService.getWorkspaceDataStats(
                                UUID.fromString(workspaceId),
                                actorEmail,
                                admin);
                return ResponseEntity.ok(WorkspaceResponseMapper.workspaceStatsToMap(stats));
        }

        @DeleteMapping("/workspaces/{workspaceId}")
        public ResponseEntity<Void> deleteWorkspace(@PathVariable String workspaceId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                workspaceService.deleteWorkspace(UUID.fromString(workspaceId), actorEmail, admin);
                return ResponseEntity.noContent().build();
        }

        @PostMapping("/workspaces/{workspaceId}/tokens")
        public ResponseEntity<Map<String, Object>> createToken(
                        @PathVariable String workspaceId,
                        @RequestBody(required = false) Map<String, String> body,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                String name = body != null ? body.get(KEY_NAME) : null;
                String description = body != null ? body.get(KEY_DESCRIPTION) : null;
                String rawToken = workspaceService.generateToken(
                                UUID.fromString(workspaceId),
                                name,
                                description,
                                actorEmail,
                                admin);

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("token", rawToken);
                return ResponseEntity.status(201).body(response);
        }

        @GetMapping("/workspaces/{workspaceId}/tokens")
        public ResponseEntity<List<Map<String, Object>>> listTokens(@PathVariable String workspaceId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                List<WorkspaceToken> tokens = workspaceService.listTokens(
                                UUID.fromString(workspaceId),
                                actorEmail,
                                admin);
                return ResponseEntity.ok(WorkspaceResponseMapper.tokenListToMaps(tokens));
        }

        @DeleteMapping("/workspaces/{workspaceId}/tokens/{tokenId}")
        public ResponseEntity<Void> revokeToken(
                        @PathVariable String workspaceId,
                        @PathVariable String tokenId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                workspaceService.revokeToken(
                                UUID.fromString(workspaceId),
                                UUID.fromString(tokenId),
                                actorEmail,
                                admin);
                return ResponseEntity.noContent().build();
        }

        @PostMapping("/workspaces/{workspaceId}/generate/{kind}")
        public ResponseEntity<Map<String, Object>> generateData(
                        @PathVariable String workspaceId,
                        @PathVariable String kind,
                        @RequestBody(required = false) GenerateDataRequest request,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
                boolean admin = AuthenticatedUser.isAdmin(authentication);
                UUID wsId = workspaceService.requireWorkspaceId(workspaceId, actorEmail, admin);
                DataGeneratorService.GenerationSummary summary = switch (kind.toLowerCase()) {
                        case "users" -> workspaceDataGeneratorService.generateUsers(
                                        wsId,
                                        request != null ? request.count() : null,
                                        actorEmail,
                                        admin);
                        case "groups" -> workspaceDataGeneratorService.generateGroups(
                                        wsId,
                                        request != null ? request.count() : null,
                                        actorEmail,
                                        admin);
                        case "relations" -> workspaceDataGeneratorService.generateRelations(
                                        wsId,
                                        request != null ? request.count() : null,
                                        actorEmail,
                                        admin);
                        case "all" -> workspaceDataGeneratorService.generateAll(
                                        wsId,
                                        request != null ? request.count() : null,
                                        actorEmail,
                                        admin);
                        default -> throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,
                                        "Unsupported generator kind: " + kind);
                };
                return ResponseEntity.ok(WorkspaceResponseMapper.generationSummaryToMap(summary));
        }
}