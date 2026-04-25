package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.ScimRequestLog;
import de.palsoftware.scim.server.ui.service.LogService;
import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.service.WorkspaceService;
import de.palsoftware.scim.server.ui.utils.LogResponseMapper;
import de.palsoftware.scim.server.ui.utils.PagedResponseMapper;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class ApiLogsController {

    private static final String KEY_CREATED_AT = "createdAt";

    private final LogService logService;
    private final WorkspaceService workspaceService;

    public ApiLogsController(LogService logService,
            WorkspaceService workspaceService) {
        this.logService = logService;
        this.workspaceService = workspaceService;
    }

    @GetMapping("/workspaces/{workspaceId}/logs")
    public ResponseEntity<Map<String, Object>> listLogs(
            @PathVariable String workspaceId,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        UUID wsId = workspaceService.requireWorkspaceId(workspaceId, actorEmail, admin);
        int safeSize = Math.max(1, Math.min(size, 200));
        int safePage = Math.max(1, page);
        PageRequest pageRequest = PageRequest.of(safePage - 1, safeSize, Sort.by(KEY_CREATED_AT).descending());
        Page<ScimRequestLog> logs = logService.listLogs(wsId, pageRequest);
        return ResponseEntity.ok(PagedResponseMapper.pagedResponse(
                logs,
                LogResponseMapper::logToMap,
                safePage,
                safeSize));
    }

    @DeleteMapping("/workspaces/{workspaceId}/logs")
    public ResponseEntity<Void> clearLogs(@PathVariable String workspaceId,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        UUID wsId = workspaceService.requireWorkspaceId(workspaceId, actorEmail, admin);
        logService.clearLogs(wsId);
        return ResponseEntity.noContent().build();
    }
}