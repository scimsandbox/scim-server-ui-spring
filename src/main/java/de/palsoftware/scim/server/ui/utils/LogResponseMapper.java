package de.palsoftware.scim.server.ui.utils;

import de.palsoftware.scim.server.ui.model.ScimRequestLog;

import java.util.LinkedHashMap;
import java.util.Map;

public final class LogResponseMapper {

    private LogResponseMapper() {}

    private static final String KEY_CREATED_AT = "createdAt";

    public static Map<String, Object> logToMap(ScimRequestLog log) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", log.getId() != null ? log.getId().toString() : null);
        map.put("workspaceId", log.getWorkspace() != null && log.getWorkspace().getId() != null
                ? log.getWorkspace().getId().toString()
                : null);
        map.put("method", log.getMethod());
        map.put("path", log.getPath());
        map.put("status", log.getStatus());
        map.put("requestBody", log.getRequestBody());
        map.put("responseBody", log.getResponseBody());
        map.put(KEY_CREATED_AT, log.getCreatedAt() != null ? log.getCreatedAt().toString() : null);
        return map;
    }
}