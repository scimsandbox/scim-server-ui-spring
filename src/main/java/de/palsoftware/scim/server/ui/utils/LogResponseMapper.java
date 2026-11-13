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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LogResponseMapper {

    private LogResponseMapper() {}

    public static final String REDACTED = "[REDACTED]";
    private static final String KEY_CREATED_AT = "createdAt";
    private static final String AUTH_HEADER_NAME = "authorization";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password",
            "access_token",
            "client_secret",
            "authorization",
            "refresh_token",
            "id_token");

    private static final Pattern JSON_SENSITIVE_KEY_PREFIX = Pattern.compile(
            "(?i)\"(?:password|access_token|client_secret|authorization|refresh_token|id_token)\"[ \\t\\r\\n]*+:[ \\t\\r\\n]*+\"");

    private static final Pattern BEARER_BASIC_TOKEN_PATTERN = Pattern.compile(
            "(?i)\\b((?:Bearer|Basic)[ \\t]++)[A-Za-z0-9._~+/=-]++");

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
        String scrubbed = redactMalformedJsonValues(text);
        scrubbed = redactAuthorizationHeaderLines(scrubbed);
        scrubbed = BEARER_BASIC_TOKEN_PATTERN.matcher(scrubbed).replaceAll("$1" + REDACTED);
        return scrubbed;
    }

    private static String redactMalformedJsonValues(String text) {
        Matcher matcher = JSON_SENSITIVE_KEY_PREFIX.matcher(text);
        if (!matcher.find()) {
            return text;
        }
        StringBuilder sb = new StringBuilder(text.length());
        int copiedTo = 0;
        do {
            int valueStart = matcher.end();
            int closingQuote = findClosingQuote(text, valueStart);
            if (closingQuote < 0) {
                int rawEnd = findLineEnd(text, valueStart);
                int valueEnd = stripTrailingCarriageReturn(text, valueStart, rawEnd);
                sb.append(text, copiedTo, valueStart).append(REDACTED);
                copiedTo = valueEnd;
                break;
            }
            sb.append(text, copiedTo, valueStart).append(REDACTED).append('"');
            copiedTo = closingQuote + 1;
        } while (matcher.find(copiedTo));
        sb.append(text, copiedTo, text.length());
        return sb.toString();
    }

    private static int findClosingQuote(String text, int fromIndex) {
        boolean escaped = false;
        for (int i = fromIndex; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                return i;
            }
        }
        return -1;
    }

    private static String redactAuthorizationHeaderLines(String text) {
        StringBuilder sb = null;
        int copiedTo = 0;
        int lineStart = 0;
        while (lineStart < text.length()) {
            int rawLineEnd = findLineEnd(text, lineStart);
            int lineEnd = stripTrailingCarriageReturn(text, lineStart, rawLineEnd);
            int valueStart = findAuthorizationValueStart(text, lineStart, lineEnd);
            if (valueStart >= 0) {
                if (sb == null) {
                    sb = new StringBuilder(text.length());
                }
                sb.append(text, copiedTo, valueStart).append(REDACTED);
                copiedTo = lineEnd;
            }
            lineStart = rawLineEnd + 1;
        }
        if (sb == null) {
            return text;
        }
        sb.append(text, copiedTo, text.length());
        return sb.toString();
    }

    private static int findLineEnd(String text, int lineStart) {
        int lineFeed = text.indexOf('\n', lineStart);
        return lineFeed < 0 ? text.length() : lineFeed;
    }

    private static int stripTrailingCarriageReturn(String text, int lineStart, int lineEnd) {
        return lineEnd > lineStart && text.charAt(lineEnd - 1) == '\r' ? lineEnd - 1 : lineEnd;
    }

    private static int findAuthorizationValueStart(String text, int lineStart, int lineEnd) {
        int keyStart = skipHorizontalWhitespace(text, lineStart, lineEnd);
        int keyEnd = keyStart + AUTH_HEADER_NAME.length();
        if (keyEnd >= lineEnd || !text.regionMatches(true, keyStart, AUTH_HEADER_NAME, 0, AUTH_HEADER_NAME.length())) {
            return -1;
        }
        int colonIndex = skipHorizontalWhitespace(text, keyEnd, lineEnd);
        if (colonIndex >= lineEnd || text.charAt(colonIndex) != ':') {
            return -1;
        }
        int valueStart = skipHorizontalWhitespace(text, colonIndex + 1, lineEnd);
        return valueStart < lineEnd ? valueStart : -1;
    }

    private static int skipHorizontalWhitespace(String text, int start, int end) {
        int idx = start;
        while (idx < end && (text.charAt(idx) == ' ' || text.charAt(idx) == '\t')) {
            idx++;
        }
        return idx;
    }
}
