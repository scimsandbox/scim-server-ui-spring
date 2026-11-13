package de.palsoftware.scim.server.ui.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.palsoftware.scim.server.ui.model.ScimRequestLog;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class LogResponseMapper {

    private LogResponseMapper() {}

    public static final String REDACTED = "[REDACTED]";
    private static final String KEY_CREATED_AT = "createdAt";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password",
            "access_token",
            "client_secret",
            "authorization",
            "refresh_token",
            "id_token");

    private static final Pattern JSON_KEY_FALLBACK_PATTERN = Pattern.compile(
            "(?i)(\"(?:password|access_token|client_secret|authorization|refresh_token|id_token)\"\\s*:\\s*\")(?:\\\\.|[^\"\\\\])*(\")");

    private static final Pattern AUTH_HEADER_LINE_PATTERN = Pattern.compile(
            "(?im)^(\\s*authorization\\s*:\\s*)([^\\r\\n]+)$");

    private static final Pattern BEARER_BASIC_TOKEN_PATTERN = Pattern.compile(
            "(?i)\\b((?:Bearer|Basic)\\s+)[A-Za-z0-9._~+/=-]+");

    public static Map<String, Object> logToMap(ScimRequestLog log) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", log.getId() != null ? log.getId().toString() : null);
        map.put("workspaceId", log.getWorkspace() != null && log.getWorkspace().getId() != null
                ? log.getWorkspace().getId().toString()
                : null);
        map.put("method", log.getMethod());
        map.put("path", log.getPath());
        map.put("status", log.getStatus());
        map.put("requestBody", redactSensitiveBody(log.getRequestBody()));
        map.put("responseBody", redactSensitiveBody(log.getResponseBody()));
        map.put(KEY_CREATED_AT, log.getCreatedAt() != null ? log.getCreatedAt().toString() : null);
        return map;
    }

    public static String redactSensitiveBody(String body) {
        if (body == null || body.isBlank()) {
            return body;
        }
        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                JsonNode root = OBJECT_MAPPER.readTree(body);
                if (redactJsonNode(root)) {
                    return OBJECT_MAPPER.writeValueAsString(root);
                }
                return body;
            } catch (JsonProcessingException ex) {
                // Fall through to text-level redaction when payload is malformed JSON or mixed HTTP dump.
            }
        }
        return redactPlainText(body);
    }

    private static boolean redactJsonNode(JsonNode node) {
        if (node == null) {
            return false;
        }
        boolean mutated = false;
        if (node instanceof ObjectNode objectNode) {
            JsonNode pathNode = objectNode.get("path");
            boolean passwordPatchOp = pathNode != null
                    && pathNode.isTextual()
                    && isPasswordPatchPath(pathNode.asText());

            for (Map.Entry<String, JsonNode> entry : objectNode.properties()) {
                String fieldName = entry.getKey();
                JsonNode valueNode = entry.getValue();
                if (isSensitiveKey(fieldName) || (passwordPatchOp && "value".equalsIgnoreCase(fieldName))) {
                    if (valueNode != null && !valueNode.isNull()) {
                        entry.setValue(objectNode.textNode(REDACTED));
                        mutated = true;
                    }
                } else if (valueNode != null && valueNode.isTextual()) {
                    String text = valueNode.asText();
                    String scrubbed = BEARER_BASIC_TOKEN_PATTERN.matcher(text).replaceAll("$1" + REDACTED);
                    if (!scrubbed.equals(text)) {
                        entry.setValue(objectNode.textNode(scrubbed));
                        mutated = true;
                    }
                } else if (redactJsonNode(valueNode)) {
                    mutated = true;
                }
            }
        } else if (node instanceof ArrayNode arrayNode) {
            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode element = arrayNode.get(i);
                if (element != null && element.isTextual()) {
                    String text = element.asText();
                    String scrubbed = BEARER_BASIC_TOKEN_PATTERN.matcher(text).replaceAll("$1" + REDACTED);
                    if (!scrubbed.equals(text)) {
                        arrayNode.set(i, arrayNode.textNode(scrubbed));
                        mutated = true;
                    }
                } else if (redactJsonNode(element)) {
                    mutated = true;
                }
            }
        }
        return mutated;
    }

    private static boolean isSensitiveKey(String key) {
        return key != null && SENSITIVE_KEYS.contains(key.trim().toLowerCase(Locale.ROOT));
    }

    private static boolean isPasswordPatchPath(String path) {
        if (path == null) {
            return false;
        }
        String normalized = path.trim().toLowerCase(Locale.ROOT);
        return "password".equals(normalized) || normalized.endsWith(":password");
    }

    private static String redactPlainText(String text) {
        String scrubbed = JSON_KEY_FALLBACK_PATTERN.matcher(text).replaceAll("$1" + REDACTED + "$2");
        scrubbed = AUTH_HEADER_LINE_PATTERN.matcher(scrubbed).replaceAll("$1" + REDACTED);
        scrubbed = BEARER_BASIC_TOKEN_PATTERN.matcher(scrubbed).replaceAll("$1" + REDACTED);
        return scrubbed;
    }
}
