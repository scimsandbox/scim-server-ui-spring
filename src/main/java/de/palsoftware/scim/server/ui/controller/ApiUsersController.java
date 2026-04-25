package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.dto.UserUpsertRequest;
import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.service.ScimAdminService;
import de.palsoftware.scim.server.ui.utils.PagedResponseMapper;
import de.palsoftware.scim.server.ui.utils.UserResponseMapper;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class ApiUsersController {

    private static final String KEY_USER_NAME = "userName";
    private static final Logger log = LoggerFactory.getLogger(ApiUsersController.class);

    private final ScimAdminService scimAdminService;

    public ApiUsersController(ScimAdminService scimAdminService) {
        this.scimAdminService = scimAdminService;
    }

    @GetMapping("/workspaces/{workspaceId}/users")
    public ResponseEntity<Map<String, Object>> listUsers(
            @PathVariable String workspaceId,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String q,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        int safeSize = Math.max(1, Math.min(size, 200));
        int safePage = Math.max(1, page);
        PageRequest pageRequest = PageRequest.of(safePage - 1, safeSize, Sort.by(KEY_USER_NAME).ascending());
        try {
            Page<ScimUser> users = scimAdminService.listUsersPage(
                    UUID.fromString(workspaceId),
                    q,
                    pageRequest,
                    actorEmail,
                    admin);
            return ResponseEntity.ok(PagedResponseMapper.pagedResponse(
                    users,
                    UserResponseMapper::userToMap,
                    safePage,
                    safeSize));
        } catch (RuntimeException ex) {
            throw failListUsers(new UserListFailureContext("list", workspaceId, safePage, safeSize, q, actorEmail, admin), ex);
        }
    }

    @GetMapping("/workspaces/{workspaceId}/users/lookup")
    public ResponseEntity<List<Map<String, Object>>> lookupUsers(
            @PathVariable String workspaceId,
            @RequestParam(required = false) String q,
            @RequestParam(defaultValue = "50") int size,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        int safeSize = Math.max(1, Math.min(size, 200));
        PageRequest pageRequest = PageRequest.of(0, safeSize, Sort.by(KEY_USER_NAME).ascending());
        try {
            Page<ScimUser> users = scimAdminService.listUsersPage(
                    UUID.fromString(workspaceId),
                    q,
                    pageRequest,
                    actorEmail,
                    admin);
            return ResponseEntity.ok(users.stream().map(UserResponseMapper::userLookupToMap).toList());
        } catch (RuntimeException ex) {
            throw failListUsers(new UserListFailureContext("lookup", workspaceId, 0, safeSize, q, actorEmail, admin), ex);
        }
    }

    private ResponseStatusException failListUsers(UserListFailureContext context, RuntimeException ex) {
        String message = "Failed to " + context.action()
                + " users for workspaceId=" + context.workspaceId()
                + ", page=" + context.page()
                + ", size=" + context.size()
                + ", query=" + context.query()
            + ", actor=" + context.actorEmail()
                + ", admin=" + context.admin();
        log.error(message, ex);
        if (ex instanceof ResponseStatusException responseStatusException) {
            return new ResponseStatusException(responseStatusException.getStatusCode(), message, ex);
        }
        return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, message, ex);
    }

    private record UserListFailureContext(
            String action,
            String workspaceId,
            int page,
            int size,
            String query,
                String actorEmail,
            boolean admin) {
    }

    @DeleteMapping("/workspaces/{workspaceId}/users")
    public ResponseEntity<Void> clearUsers(@PathVariable String workspaceId,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        scimAdminService.deleteAllUsers(UUID.fromString(workspaceId), actorEmail, admin);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/workspaces/{workspaceId}/users")
    public ResponseEntity<Map<String, Object>> createUser(
            @PathVariable String workspaceId,
            @RequestBody UserUpsertRequest request,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        ScimUser user = scimAdminService.createUser(
                UUID.fromString(workspaceId),
                request,
            actorEmail,
                admin);
        return ResponseEntity.status(201).body(UserResponseMapper.userToMap(user));
    }

    @PutMapping("/workspaces/{workspaceId}/users/{userId}")
    public ResponseEntity<Map<String, Object>> updateUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            @RequestBody UserUpsertRequest request,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        ScimUser user = scimAdminService.updateUser(
                UUID.fromString(workspaceId),
                UUID.fromString(userId),
                request,
            actorEmail,
                admin);
        return ResponseEntity.ok(UserResponseMapper.userToMap(user));
    }

    @DeleteMapping("/workspaces/{workspaceId}/users/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            Authentication authentication) {
        String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
        scimAdminService.deleteUser(
                UUID.fromString(workspaceId),
                UUID.fromString(userId),
            actorEmail,
                admin);
        return ResponseEntity.noContent().build();
    }
}