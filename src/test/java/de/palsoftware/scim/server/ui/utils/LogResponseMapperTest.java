package de.palsoftware.scim.server.ui.utils;

import de.palsoftware.scim.server.ui.model.ScimRequestLog;
import de.palsoftware.scim.server.ui.model.Workspace;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class LogResponseMapperTest {

    @Test
    void logToMapRedactsPasswordsTokensSecretsAndAuthorizationInJsonBodies() {
        ScimRequestLog log = new ScimRequestLog();
        log.setId(UUID.randomUUID());
        log.setMethod("POST");
        log.setPath("/scim/v2/Users");
        log.setStatus(201);
        log.setCreatedAt(Instant.parse("2026-01-01T00:00:00Z"));
        log.setRequestBody("""
                {
                  "userName": "alice",
                  "password": "SuperSecretPassword!",
                  "client_secret": "top-secret-client",
                  "headers": {
                    "Authorization": "Bearer raw-scim-bearer-token"
                  }
                }
                """);
        log.setResponseBody("""
                {
                  "id": "123",
                  "access_token": "minted-access-token",
                  "note": "Used Bearer inline-secret-token"
                }
                """);

        Map<String, Object> mapped = LogResponseMapper.logToMap(log);
        String requestBody = (String) mapped.get("requestBody");
        String responseBody = (String) mapped.get("responseBody");

        assertThat(requestBody)
                .contains("\"userName\":\"alice\"")
                .contains("\"password\":\"[REDACTED]\"")
                .contains("\"client_secret\":\"[REDACTED]\"")
                .contains("\"Authorization\":\"[REDACTED]\"")
                .doesNotContain("SuperSecretPassword!")
                .doesNotContain("top-secret-client")
                .doesNotContain("raw-scim-bearer-token");

        assertThat(responseBody)
                .contains("\"access_token\":\"[REDACTED]\"")
                .contains("Bearer [REDACTED]")
                .doesNotContain("minted-access-token")
                .doesNotContain("inline-secret-token");
    }

    @Test
    void redactSensitiveBodyRedactsScimPatchPasswordOperations() {
        String patchBody = """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    {"op": "replace", "path": "password", "value": "PatchedSecret123!"},
                    {"op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:password", "value": "SchemaSecret456!"},
                    {"op": "replace", "path": "displayName", "value": "Alice Smith"}
                  ]
                }
                """;

        String redacted = LogResponseMapper.redactSensitiveBody(patchBody);

        assertThat(redacted)
                .contains("Alice Smith")
                .doesNotContain("PatchedSecret123!")
                .doesNotContain("SchemaSecret456!");
    }

    @Test
    void redactSensitiveBodyRedactsRawHttpHeadersAndMalformedJsonFallback() {
        String rawDump = """
                POST /scim/v2/Users HTTP/1.1
                Authorization: Bearer secret-header-token-999
                Content-Type: application/scim+json

                {"userName":"bob","password":"UnclosedJsonPassword"
                """;

        String redacted = LogResponseMapper.redactSensitiveBody(rawDump);

        assertThat(redacted)
                .contains("Authorization: [REDACTED]")
                .contains("\"password\":\"[REDACTED]\"")
                .doesNotContain("secret-header-token-999")
                .doesNotContain("UnclosedJsonPassword");
    }

    @Test
    void redactSensitiveBodyHandlesEscapedQuotesLargePayloadsAndTruncatedStringsInLinearTime() {
        String largeEscapedSecret = ("a\\\"b\\\\".repeat(10_000)) + "tailSecret";
        String malformed = "{\"password\" : \"" + largeEscapedSecret + "\", \"refresh_token\":\"rt-123\"";

        String redacted = LogResponseMapper.redactSensitiveBody(malformed);

        assertThat(redacted)
                .isEqualTo("{\"password\" : \"[REDACTED]\", \"refresh_token\":\"[REDACTED]\"");

        String truncatedMidPassword = "{\"userName\":\"bob\",\"password\":\"TruncatedWithoutClosingQuote\r\n";
        assertThat(LogResponseMapper.redactSensitiveBody(truncatedMidPassword))
                .isEqualTo("{\"userName\":\"bob\",\"password\":\"[REDACTED]\r\n");
    }

    @Test
    void redactSensitiveBodyHandlesAuthorizationHeaderEdgeCasesAndJsonArrays() {
        String headers = "\tAuthorization\t:\tBasic dXNlcjpwYXNz==\r\n"
                + "Authorization:   \r\n"
                + "Authorization-Extra: keep-me\r\n"
                + "X-Note: nothing sensitive here";

        String redactedHeaders = LogResponseMapper.redactSensitiveBody(headers);
        assertThat(redactedHeaders)
                .contains("\tAuthorization\t:\t[REDACTED]\r\n")
                .contains("Authorization:   \r\n")
                .contains("Authorization-Extra: keep-me\r\n")
                .doesNotContain("dXNlcjpwYXNz==");

        String jsonArray = "[\"Bearer token-in-array\", {\"id_token\": \"jwt-secret\", \"empty\": null}, \"plain\"]";
        assertThat(LogResponseMapper.redactSensitiveBody(jsonArray))
                .contains("Bearer [REDACTED]")
                .contains("\"id_token\":\"[REDACTED]\"")
                .doesNotContain("token-in-array")
                .doesNotContain("jwt-secret");

        String cleanJson = "{\"id\":\"1\",\"userName\":\"alice\"}";
        assertThat(LogResponseMapper.redactSensitiveBody(cleanJson)).isSameAs(cleanJson);
        assertThat(LogResponseMapper.redactSensitiveBody(null)).isNull();
        assertThat(LogResponseMapper.redactSensitiveBody("   ")).isEqualTo("   ");

        Workspace ws = new Workspace();
        UUID wsId = UUID.randomUUID();
        ws.setId(wsId);
        ScimRequestLog logWithWorkspace = new ScimRequestLog();
        logWithWorkspace.setWorkspace(ws);
        assertThat(LogResponseMapper.logToMap(logWithWorkspace))
                .containsEntry("workspaceId", wsId.toString())
                .containsEntry("id", null)
                .containsEntry("createdAt", null);
    }
}
