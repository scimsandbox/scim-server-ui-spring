package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.dto.GroupUpsertRequest;
import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import de.palsoftware.scim.server.ui.utils.GroupResponseMapper;
import de.palsoftware.scim.server.ui.utils.PagedResponseMapper;
import de.palsoftware.scim.server.ui.service.ScimAdminService;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
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

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class ApiGroupsController {

        private static final String KEY_DISPLAY_NAME = "displayName";

        private final ScimAdminService scimAdminService;

        public ApiGroupsController(ScimAdminService scimAdminService) {
                this.scimAdminService = scimAdminService;
        }

        @GetMapping("/workspaces/{workspaceId}/groups")
        public ResponseEntity<Map<String, Object>> listGroups(
                        @PathVariable String workspaceId,
                        @RequestParam(defaultValue = "1") int page,
                        @RequestParam(defaultValue = "20") int size,
                        @RequestParam(required = false) String q,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
                int safeSize = Math.max(1, Math.min(size, 200));
                int safePage = Math.max(1, page);
                PageRequest pageRequest = PageRequest.of(safePage - 1, safeSize, Sort.by(KEY_DISPLAY_NAME).ascending());
                Page<ScimGroup> groups = scimAdminService.listGroupsPage(
                                UUID.fromString(workspaceId),
                                q,
                                pageRequest,
                                actorEmail,
                                admin);
                return ResponseEntity.ok(PagedResponseMapper.pagedResponse(
                                groups,
                                GroupResponseMapper::groupToMap,
                                safePage,
                                safeSize));
        }

        @GetMapping("/workspaces/{workspaceId}/groups/lookup")
        public ResponseEntity<List<Map<String, Object>>> lookupGroups(
                        @PathVariable String workspaceId,
                        @RequestParam(required = false) String q,
                        @RequestParam(defaultValue = "50") int size,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
                int safeSize = Math.max(1, Math.min(size, 200));
                PageRequest pageRequest = PageRequest.of(0, safeSize, Sort.by(KEY_DISPLAY_NAME).ascending());
                Page<ScimGroup> groups = scimAdminService.listGroupsPage(
                                UUID.fromString(workspaceId),
                                q,
                                pageRequest,
                                actorEmail,
                                admin);
                return ResponseEntity.ok(groups.stream().map(GroupResponseMapper::groupLookupToMap).toList());
        }

        @DeleteMapping("/workspaces/{workspaceId}/groups")
        public ResponseEntity<Void> clearGroups(@PathVariable String workspaceId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
                scimAdminService.deleteAllGroups(UUID.fromString(workspaceId), actorEmail, admin);
                return ResponseEntity.noContent().build();
        }

        @PostMapping("/workspaces/{workspaceId}/groups")
        public ResponseEntity<Map<String, Object>> createGroup(
                        @PathVariable String workspaceId,
                        @RequestBody GroupUpsertRequest request,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
                ScimGroup group = scimAdminService.createGroup(
                                UUID.fromString(workspaceId),
                                request,
                                actorEmail,
                                admin);
                return ResponseEntity.status(201).body(GroupResponseMapper.groupToMap(group));
        }

        @PutMapping("/workspaces/{workspaceId}/groups/{groupId}")
        public ResponseEntity<Map<String, Object>> updateGroup(
                        @PathVariable String workspaceId,
                        @PathVariable String groupId,
                        @RequestBody GroupUpsertRequest request,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
                ScimGroup group = scimAdminService.updateGroup(
                                UUID.fromString(workspaceId),
                                UUID.fromString(groupId),
                                request,
                                actorEmail,
                                admin);
                return ResponseEntity.ok(GroupResponseMapper.groupToMap(group));
        }

        @DeleteMapping("/workspaces/{workspaceId}/groups/{groupId}")
        public ResponseEntity<Void> deleteGroup(
                        @PathVariable String workspaceId,
                        @PathVariable String groupId,
                        Authentication authentication) {
                String actorEmail = AuthenticatedUser.email(authentication);
        boolean admin = AuthenticatedUser.isAdmin(authentication);
                scimAdminService.deleteGroup(
                                UUID.fromString(workspaceId),
                                UUID.fromString(groupId),
                                actorEmail,
                                admin);
                return ResponseEntity.noContent().build();
        }
}