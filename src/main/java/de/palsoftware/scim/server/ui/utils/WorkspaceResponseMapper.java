package de.palsoftware.scim.server.ui.utils;

import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.model.WorkspaceToken;
import de.palsoftware.scim.server.ui.repository.WorkspaceDataStats;
import de.palsoftware.scim.server.ui.model.MgmtUser;
import de.palsoftware.scim.server.ui.repository.MgmtUserRepository;
import de.palsoftware.scim.server.ui.service.DataGeneratorService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public final class WorkspaceResponseMapper {

    private WorkspaceResponseMapper() {
    }

    private static final String KEY_NAME = "name";
    private static final String KEY_DESCRIPTION = "description";
    private static final String KEY_CREATED_AT = "createdAt";
    private static final String KEY_TOTAL = "total";

    public static List<Map<String, Object>> workspaceListToMaps(List<Workspace> workspaces,
            MgmtUserRepository mgmtUserRepository) {
        List<String> ownerIds = workspaces.stream()
                .map(Workspace::getCreatedByUsername)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        Map<String, String> ownerEmails = mgmtUserRepository.findAllById(ownerIds).stream()
            .collect(Collectors.toMap(MgmtUser::getEmail, MgmtUser::getEmail));
        return workspaces.stream()
                .map(workspace -> workspaceToMap(workspace, ownerEmails))
                .toList();
    }

    public static Map<String, Object> workspaceToMap(Workspace workspace, MgmtUserRepository mgmtUserRepository) {
        String ownerName = workspace.getCreatedByUsername() != null
                ? mgmtUserRepository.findById(workspace.getCreatedByUsername())
                        .map(MgmtUser::getEmail)
                .orElse(workspace.getCreatedByUsername())
                : null;
        return buildWorkspaceMap(workspace, ownerName);
    }

    public static Map<String, Object> workspaceDetailToMap(Workspace workspace, WorkspaceDataStats stats,
            MgmtUserRepository mgmtUserRepository) {
        Map<String, Object> map = workspaceToMap(workspace, mgmtUserRepository);
        map.put("stats", workspaceStatsToMap(stats));
        return map;
    }

    public static Map<String, Object> workspaceStatsToMap(WorkspaceDataStats stats) {
        Map<String, Object> map = new LinkedHashMap<>();

        Map<String, Object> objects = new LinkedHashMap<>();
        objects.put(KEY_TOTAL, stats.objectCount());
        objects.put("users", stats.userCount());
        objects.put("groups", stats.groupCount());
        objects.put("tokens", stats.tokenCount());
        objects.put("logs", stats.logCount());
        objects.put("userAttributeRows", stats.userAttributeObjectCount());

        Map<String, Object> userAttributes = new LinkedHashMap<>();
        userAttributes.put("emails", stats.emailCount());
        userAttributes.put("phoneNumbers", stats.phoneNumberCount());
        userAttributes.put("addresses", stats.addressCount());
        userAttributes.put("entitlements", stats.entitlementCount());
        userAttributes.put("roles", stats.roleCount());
        userAttributes.put("ims", stats.imCount());
        userAttributes.put("photos", stats.photoCount());
        userAttributes.put("x509Certificates", stats.x509CertificateCount());
        objects.put("userAttributes", userAttributes);

        Map<String, Object> relations = new LinkedHashMap<>();
        relations.put(KEY_TOTAL, stats.relationCount());
        relations.put("groupMemberships", stats.groupMembershipCount());

        Map<String, Object> storage = new LinkedHashMap<>();
        storage.put("estimatedRowBytes", stats.estimatedRowBytes());
        storage.put("storedRows", stats.storedRowCount());

        map.put("objects", objects);
        map.put("relations", relations);
        map.put("storage", storage);
        return map;
    }

    public static List<Map<String, Object>> tokenListToMaps(List<WorkspaceToken> tokens) {
        return tokens.stream().map(WorkspaceResponseMapper::tokenToMap).toList();
    }

    public static Map<String, Object> generationSummaryToMap(DataGeneratorService.GenerationSummary summary) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("requestedCount", summary.requestedCount());
        response.put("appliedCount", summary.appliedCount());
        response.put("usersCreated", summary.usersCreated());
        response.put("groupsCreated", summary.groupsCreated());
        response.put("relationsCreated", summary.relationsCreated());
        return response;
    }

    private static Map<String, Object> workspaceToMap(Workspace workspace, Map<String, String> ownerEmails) {
        String ownerName = workspace.getCreatedByUsername() != null
                ? ownerEmails.getOrDefault(workspace.getCreatedByUsername(), workspace.getCreatedByUsername())
                : null;
        return buildWorkspaceMap(workspace, ownerName);
    }

    private static Map<String, Object> buildWorkspaceMap(Workspace workspace, String ownerDisplayName) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", workspace.getId().toString());
        map.put(KEY_NAME, workspace.getName());
        map.put(KEY_DESCRIPTION, workspace.getDescription());
        map.put("createdByUsername", workspace.getCreatedByUsername());
        map.put("createdByDisplayName", ownerDisplayName);
        map.put(KEY_CREATED_AT, workspace.getCreatedAt() != null ? workspace.getCreatedAt().toString() : null);
        map.put("updatedAt", workspace.getUpdatedAt() != null ? workspace.getUpdatedAt().toString() : null);
        return map;
    }

    private static Map<String, Object> tokenToMap(WorkspaceToken token) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", token.getId().toString());
        map.put(KEY_NAME, token.getName());
        map.put(KEY_DESCRIPTION, token.getDescription());
        map.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        map.put("revoked", token.isRevoked());
        map.put(KEY_CREATED_AT, token.getCreatedAt() != null ? token.getCreatedAt().toString() : null);
        return map;
    }
}