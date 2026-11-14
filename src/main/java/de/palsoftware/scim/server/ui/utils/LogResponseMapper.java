package de.palsoftware.scim.server.ui.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.palsoftware.scim.server.ui.model.ScimRequestLog;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
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
    private static final String PROXY_AUTH_HEADER_NAME = "proxy-authorization";
    private static final String BEARER_SCHEME = "Bearer";
    private static final String BASIC_SCHEME = "Basic";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password",
            "access_token",
            "client_secret",
            "authorization",
            "proxy-authorization",
            "proxy_authorization",
            "refresh_token",
            "id_token");

    private static final Pattern JSON_SENSITIVE_KEY_PREFIX = Pattern.compile(
            "(?i)\"(?:[^\":\\r\\n\\\\]*+:)*+(?:password|access_token|client_secret|authorization|proxy[-_]authorization|refresh_token|id_token)\"[ \\t\\r\\n]*+:[ \\t\\r\\n]*+\"");

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
                    String scrubbed = redactInlineAuthTokens(text);
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
                    String scrubbed = redactInlineAuthTokens(text);
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
        if (key == null) {
            return false;
        }
        String normalized = key.trim().toLowerCase(Locale.ROOT);
        if (SENSITIVE_KEYS.contains(normalized)) {
            return true;
        }
        int lastColon = normalized.lastIndexOf(':');
        return lastColon >= 0 && SENSITIVE_KEYS.contains(normalized.substring(lastColon + 1));
    }

    private static boolean isPasswordPatchPath(String path) {
        if (path == null) {
            return false;
        }
        String normalized = path.trim().toLowerCase(Locale.ROOT);
        int bracketIdx = normalized.indexOf('[');
        String basePath = bracketIdx >= 0 ? normalized.substring(0, bracketIdx).trim() : normalized;
        if (basePath.endsWith(".value")) {
            basePath = basePath.substring(0, basePath.length() - ".value".length());
        }
        return "password".equals(basePath) || basePath.endsWith(":password");
    }

    private static String redactPlainText(String text) {
        String scrubbed = redactPatternValues(text, JSON_SENSITIVE_KEY_PREFIX);
        scrubbed = redactMalformedPatchPasswordSegments(scrubbed);
        scrubbed = redactAuthorizationHeaderLines(scrubbed);
        scrubbed = redactInlineAuthTokens(scrubbed);
        return scrubbed;
    }

    private static String redactPatternValues(String text, Pattern prefixPattern) {
        Matcher matcher = prefixPattern.matcher(text);
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
            } else {
                sb.append(text, copiedTo, valueStart).append(REDACTED).append('"');
                copiedTo = closingQuote + 1;
            }
        } while (copiedTo < text.length() && matcher.find(copiedTo));
        sb.append(text, copiedTo, text.length());
        return sb.toString();
    }

    /**
     * Linear-time scanner over flat {@code {...}} JSON object segments (including segments truncated at EOF)
     * that redacts {@code "value": "..."} whenever {@code "path"} in the same flat object targets {@code password},
     * regardless of key order ({@code "value"} before {@code "path"}) or intervening fields like {@code "op"}.
     */
    private static String redactMalformedPatchPasswordSegments(String text) {
        if (!containsIgnoreCase(text, "password")) {
            return text;
        }
        List<ValueSpan> redactions = null;
        boolean inString = false;
        boolean escaped = false;
        int flatObjStart = -1;

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inString) {
                if (ch == '\n' || ch == '\r') {
                    inString = false;
                    escaped = false;
                } else if (escaped) {
                    escaped = false;
                } else if (ch == '\\') {
                    escaped = true;
                } else if (ch == '"') {
                    inString = false;
                }
            } else if (ch == '"') {
                inString = true;
            } else if (ch == '{') {
                flatObjStart = i;
            } else if (ch == '}' && flatObjStart >= 0) {
                redactions = collectPatchValueSpansInFlatSegment(text, flatObjStart + 1, i, redactions);
                flatObjStart = -1;
            }
        }
        if (flatObjStart >= 0) {
            redactions = collectPatchValueSpansInFlatSegment(text, flatObjStart + 1, text.length(), redactions);
        }

        if (redactions == null || redactions.isEmpty()) {
            return text;
        }
        StringBuilder sb = new StringBuilder(text.length());
        int copiedTo = 0;
        for (ValueSpan span : redactions) {
            sb.append(text, copiedTo, span.valueStart()).append(REDACTED);
            if (span.hasClosingQuote()) {
                sb.append('"');
            }
            copiedTo = span.replaceEnd();
        }
        sb.append(text, copiedTo, text.length());
        return sb.toString();
    }

    private static List<ValueSpan> collectPatchValueSpansInFlatSegment(String text,
                                                                       int start,
                                                                       int end,
                                                                       List<ValueSpan> target) {
        boolean hasPasswordPath = false;
        List<ValueSpan> segmentValues = null;
        int i = start;
        while (i < end) {
            i = skipJsonDelimitersAndWhitespace(text, i, end);
            if (i >= end || text.charAt(i) != '"') {
                i++;
                continue;
            }
            int keyStart = i + 1;
            int keyEnd = findClosingQuoteInRange(text, keyStart, end);
            if (keyEnd < 0) {
                break;
            }
            String key = text.substring(keyStart, keyEnd);
            int colon = skipJsonWhitespace(text, keyEnd + 1, end);
            if (colon >= end || text.charAt(colon) != ':') {
                i = keyEnd + 1;
                continue;
            }
            int valToken = skipJsonWhitespace(text, colon + 1, end);
            if (valToken >= end) {
                break;
            }
            if (text.charAt(valToken) == '"') {
                int valStart = valToken + 1;
                int valClose = findClosingQuoteInRange(text, valStart, end);
                if ("path".equalsIgnoreCase(key)) {
                    int pathEnd = valClose >= 0
                            ? valClose
                            : stripTrailingCarriageReturn(text, valStart, Math.min(end, findLineEnd(text, valStart)));
                    if (isPasswordPatchPath(text.substring(valStart, pathEnd))) {
                        hasPasswordPath = true;
                    }
                } else if ("value".equalsIgnoreCase(key)) {
                    if (segmentValues == null) {
                        segmentValues = new ArrayList<>(1);
                    }
                    if (valClose >= 0) {
                        segmentValues.add(new ValueSpan(valStart, valClose + 1, true));
                    } else {
                        int rawLineEnd = Math.min(end, findLineEnd(text, valStart));
                        int lineEnd = stripTrailingCarriageReturn(text, valStart, rawLineEnd);
                        segmentValues.add(new ValueSpan(valStart, lineEnd, false));
                    }
                }
                i = valClose >= 0 ? valClose + 1 : Math.min(end, findLineEnd(text, valStart));
            } else {
                i = skipNonStringScalar(text, valToken, end);
            }
        }

        if (hasPasswordPath && segmentValues != null && !segmentValues.isEmpty()) {
            List<ValueSpan> out = target != null ? target : new ArrayList<>();
            out.addAll(segmentValues);
            return out;
        }
        return target;
    }

    private static int findClosingQuoteInRange(String text, int fromIndex, int limit) {
        boolean escaped = false;
        for (int i = fromIndex; i < limit; i++) {
            char ch = text.charAt(i);
            if (ch == '\n' || ch == '\r') {
                return -1;
            }
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

    private static int skipJsonWhitespace(String text, int start, int end) {
        int i = start;
        while (i < end) {
            char ch = text.charAt(i);
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                i++;
            } else {
                break;
            }
        }
        return i;
    }

    private static int skipJsonDelimitersAndWhitespace(String text, int start, int end) {
        int i = start;
        while (i < end) {
            char ch = text.charAt(i);
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ',') {
                i++;
            } else {
                break;
            }
        }
        return i;
    }

    private static int skipNonStringScalar(String text, int start, int end) {
        int i = start;
        while (i < end) {
            char ch = text.charAt(i);
            if (ch == ',' || ch == '"' || ch == '}' || ch == '{') {
                break;
            }
            i++;
        }
        return i;
    }

    private static boolean containsIgnoreCase(String text, String needleLower) {
        int nLen = needleLower.length();
        int limit = text.length() - nLen;
        for (int i = 0; i <= limit; i++) {
            if (text.regionMatches(true, i, needleLower, 0, nLen)) {
                return true;
            }
        }
        return false;
    }

    private record ValueSpan(int valueStart, int replaceEnd, boolean hasClosingQuote) {
    }

    private static int findClosingQuote(String text, int fromIndex) {
        return findClosingQuoteInRange(text, fromIndex, text.length());
    }

    /**
     * Linear-time scanner for inline {@code Bearer <token>} and {@code Basic <credentials>} substrings.
     * Supports full RFC 6750 b68token / Base64 / Base64URL alphabets (including tokens starting or ending
     * with {@code -}, {@code _}, {@code +}, {@code /}, {@code ~}, {@code =}) while leaving ordinary prose
     * and SCIM names such as {@code "Basic Users"} or {@code "OAuth Bearer Token"} unredacted.
     */
    private static String redactInlineAuthTokens(String text) {
        int len = text.length();
        if (len < 10) {
            return text;
        }
        StringBuilder sb = null;
        int copiedTo = 0;
        int i = 0;
        while (i < len) {
            if (i == 0 || !isWordChar(text.charAt(i - 1))) {
                boolean isBearer = text.regionMatches(true, i, BEARER_SCHEME, 0, BEARER_SCHEME.length());
                boolean isBasic = !isBearer && text.regionMatches(true, i, BASIC_SCHEME, 0, BASIC_SCHEME.length());
                if (isBearer || isBasic) {
                    int schemeEnd = i + (isBearer ? BEARER_SCHEME.length() : BASIC_SCHEME.length());
                    if (schemeEnd < len && isHorizontalWhitespace(text.charAt(schemeEnd))) {
                        int wsEnd = skipHorizontalWhitespace(text, schemeEnd, len);
                        int rawTokenEnd = scanTokenEnd(text, wsEnd, len);
                        int tokenEnd = trimTrailingPeriods(text, wsEnd, rawTokenEnd);
                        if (tokenEnd > wsEnd) {
                            String candidate = text.substring(wsEnd, tokenEnd);
                            boolean shouldRedact = isBearer
                                    ? isLikelyBearerToken(candidate)
                                    : isLikelyBasicCredential(candidate);
                            if (shouldRedact) {
                                if (sb == null) {
                                    sb = new StringBuilder(len);
                                }
                                sb.append(text, copiedTo, wsEnd).append(REDACTED);
                                copiedTo = tokenEnd;
                                i = tokenEnd;
                                continue;
                            }
                        }
                        // Advance to wsEnd (not rawTokenEnd) so adjacent scheme words such as
                        // "Bearer Bearer <token>" or "Basic Bearer <token>" are evaluated next.
                        i = wsEnd;
                        continue;
                    }
                }
            }
            i++;
        }
        if (sb == null) {
            return text;
        }
        sb.append(text, copiedTo, len);
        return sb.toString();
    }

    private static boolean isLikelyBearerToken(String candidate) {
        int len = candidate.length();
        if (len < 6) {
            return false;
        }
        int alphaNumCount = 0;
        boolean hasNonLetterTokenChar = false;
        boolean hasUpper = false;
        boolean hasLower = false;
        for (int i = 0; i < len; i++) {
            char ch = candidate.charAt(i);
            if (ch >= 'A' && ch <= 'Z') {
                hasUpper = true;
                alphaNumCount++;
            } else if (ch >= 'a' && ch <= 'z') {
                hasLower = true;
                alphaNumCount++;
            } else if (ch >= '0' && ch <= '9') {
                hasNonLetterTokenChar = true;
                alphaNumCount++;
            } else {
                hasNonLetterTokenChar = true;
            }
        }
        if (alphaNumCount < 4) {
            return false;
        }
        return hasNonLetterTokenChar || (len >= 24 && hasUpper && hasLower);
    }

    private static boolean isLikelyBasicCredential(String candidate) {
        if (candidate.length() < 4) {
            return false;
        }
        if (decodesToColonSeparatedCredential(candidate)) {
            return true;
        }
        // Fallback for non-Base64 synthetic Basic tokens in logs/tests (never matches plain English words).
        if (candidate.length() < 8) {
            return false;
        }
        int alphaNumCount = 0;
        boolean hasNonLetterTokenChar = false;
        for (int i = 0; i < candidate.length(); i++) {
            char ch = candidate.charAt(i);
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                alphaNumCount++;
            } else if (ch >= '0' && ch <= '9') {
                alphaNumCount++;
                hasNonLetterTokenChar = true;
            } else {
                hasNonLetterTokenChar = true;
            }
        }
        return alphaNumCount >= 4 && hasNonLetterTokenChar;
    }

    private static boolean decodesToColonSeparatedCredential(String candidate) {
        int end = candidate.length();
        int paddingChars = 0;
        while (end > 0 && candidate.charAt(end - 1) == '=') {
            end--;
            paddingChars++;
            if (paddingChars > 2) {
                return false;
            }
        }
        if (end < 4 || (end % 4) == 1) {
            return false;
        }
        boolean urlSafe = false;
        boolean standard = false;
        for (int i = 0; i < end; i++) {
            char ch = candidate.charAt(i);
            if (ch == '+' || ch == '/') {
                standard = true;
            } else if (ch == '-' || ch == '_') {
                urlSafe = true;
            } else if (!isAsciiAlphanumeric(ch)) {
                return false;
            }
        }
        if (standard && urlSafe) {
            return false;
        }
        String unpadded = candidate.substring(0, end);
        try {
            byte[] decoded = (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(unpadded);
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(decoded))
                    .toString();
            int colonIdx = text.indexOf(':');
            if (colonIdx < 0) {
                return false;
            }
            for (int i = 0; i < text.length(); i++) {
                char ch = text.charAt(i);
                if (ch < 0x20 || ch == 0x7F) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException | CharacterCodingException ex) {
            return false;
        }
    }

    private static int scanTokenEnd(String text, int start, int limit) {
        int idx = start;
        while (idx < limit && isTokenChar(text.charAt(idx))) {
            idx++;
        }
        return idx;
    }

    private static int trimTrailingPeriods(String text, int start, int end) {
        int idx = end;
        while (idx > start && text.charAt(idx - 1) == '.') {
            idx--;
        }
        return idx;
    }

    private static boolean isWordChar(char ch) {
        return isAsciiAlphanumeric(ch) || ch == '_';
    }

    private static boolean isAsciiAlphanumeric(char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
    }

    private static boolean isTokenChar(char ch) {
        return isAsciiAlphanumeric(ch)
                || ch == '.'
                || ch == '_'
                || ch == '~'
                || ch == '+'
                || ch == '/'
                || ch == '='
                || ch == '-';
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
        int matchedHeaderLen = matchAuthHeaderName(text, keyStart, lineEnd);
        if (matchedHeaderLen < 0) {
            return -1;
        }
        int colonIndex = skipHorizontalWhitespace(text, keyStart + matchedHeaderLen, lineEnd);
        if (colonIndex >= lineEnd || text.charAt(colonIndex) != ':') {
            return -1;
        }
        int valueStart = skipHorizontalWhitespace(text, colonIndex + 1, lineEnd);
        return valueStart < lineEnd ? valueStart : -1;
    }

    private static int matchAuthHeaderName(String text, int keyStart, int lineEnd) {
        if (keyStart + AUTH_HEADER_NAME.length() < lineEnd
                && text.regionMatches(true, keyStart, AUTH_HEADER_NAME, 0, AUTH_HEADER_NAME.length())) {
            return AUTH_HEADER_NAME.length();
        }
        if (keyStart + PROXY_AUTH_HEADER_NAME.length() < lineEnd
                && text.regionMatches(true, keyStart, PROXY_AUTH_HEADER_NAME, 0, PROXY_AUTH_HEADER_NAME.length())) {
            return PROXY_AUTH_HEADER_NAME.length();
        }
        return -1;
    }

    private static boolean isHorizontalWhitespace(char ch) {
        return ch == ' ' || ch == '\t';
    }

    private static int skipHorizontalWhitespace(String text, int start, int end) {
        int idx = start;
        while (idx < end && isHorizontalWhitespace(text.charAt(idx))) {
            idx++;
        }
        return idx;
    }
}
