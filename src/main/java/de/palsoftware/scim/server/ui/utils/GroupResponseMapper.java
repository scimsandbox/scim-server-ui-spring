package de.palsoftware.scim.server.ui.utils;

import de.palsoftware.scim.server.ui.model.ScimGroup;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public final class GroupResponseMapper {

    private GroupResponseMapper() {}

    private static final String KEY_DISPLAY_NAME = "displayName";
    private static final String KEY_EXTERNAL_ID = "externalId";
    private static final String KEY_VALUE = "value";
    private static final String KEY_TYPE = "type";
    private static final String KEY_DISPLAY = "display";
    private static final String KEY_CREATED_AT = "createdAt";
    private static final String KEY_LAST_MODIFIED = "lastModified";

    public static Map<String, Object> groupToMap(ScimGroup group) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", group.getId().toString());
        map.put(KEY_DISPLAY_NAME, group.getDisplayName());
        map.put(KEY_EXTERNAL_ID, group.getExternalId());
        map.put("members", group.getMembers().stream()
                .map(member -> {
                    Map<String, Object> memberMap = new LinkedHashMap<>();
                    memberMap.put(KEY_VALUE,
                            member.getMemberValue() != null ? member.getMemberValue().toString() : null);
                    memberMap.put(KEY_TYPE, member.getMemberType());
                    memberMap.put(KEY_DISPLAY, member.getDisplay());
                    return memberMap;
                })
                .toList());
        map.put(KEY_CREATED_AT, group.getCreatedAt() != null ? group.getCreatedAt().toString() : null);
        map.put(KEY_LAST_MODIFIED, group.getLastModified() != null ? group.getLastModified().toString() : null);
        map.put("meta", metaToMap(group.getCreatedAt(), group.getLastModified(), group.getVersion()));
        return map;
    }

    public static Map<String, Object> groupLookupToMap(ScimGroup group) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", group.getId().toString());
        map.put(KEY_DISPLAY_NAME, group.getDisplayName());
        map.put(KEY_EXTERNAL_ID, group.getExternalId());
        return map;
    }

    private static Map<String, Object> metaToMap(Instant createdAt, Instant lastModified, Long version) {
        Map<String, Object> meta = new LinkedHashMap<>(3, 1.0f);
        meta.put(KEY_CREATED_AT, createdAt != null ? createdAt.toString() : null);
        meta.put(KEY_LAST_MODIFIED, lastModified != null ? lastModified.toString() : null);
        meta.put("version", version);
        return meta;
    }
}