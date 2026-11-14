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

    @Test
    void redactSensitiveBodyPreservesGroupNamesAndDescriptionsStartingWithBasicOrBearer() {
        String groupJson = """
                {
                  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                  "displayName": "Basic Users",
                  "description": "Group for Basic Users.",
                  "authenticationSchemes": [
                    {
                      "name": "OAuth Bearer Token",
                      "description": "Authentication scheme using the OAuth Bearer Token Standard"
                    },
                    {
                      "name": "HTTP Basic",
                      "description": "Authentication scheme using the HTTP Basic Standard"
                    }
                  ],
                  "title": "Bearer Authentication"
                }
                """;

        assertThat(LogResponseMapper.redactSensitiveBody(groupJson))
                .isSameAs(groupJson)
                .contains("\"displayName\": \"Basic Users\"")
                .contains("\"name\": \"OAuth Bearer Token\"")
                .contains("HTTP Basic Standard")
                .contains("Bearer Authentication")
                .doesNotContain("[REDACTED]");

        String mixedPlainText = "Group: Basic Users\n"
                + "Scheme: OAuth Bearer Token\n"
                + "Inline basic cred: Basic dXNlcjpwYXNz\n"
                + "Inline bearer cred: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig_123.";

        assertThat(LogResponseMapper.redactSensitiveBody(mixedPlainText))
                .contains("Group: Basic Users\n")
                .contains("Scheme: OAuth Bearer Token\n")
                .contains("Inline basic cred: Basic [REDACTED]\n")
                .contains("Inline bearer cred: Bearer [REDACTED].")
                .doesNotContain("dXNlcjpwYXNz")
                .doesNotContain("eyJhbGciOiJIUzI1NiJ9");
    }

    @Test
    void redactSensitiveBodyRedactsMultiLineTruncatedStringsSchemaQualifiedKeysAndProxyAuthorization() {
        String multiLineMalformed = "{\"password\":\"unclosedLine1Secret\n"
                + "{\"access_token\":\"line2Secret\","
                + "\"urn:ietf:params:scim:schemas:core:2.0:User:password\":\"schemaMalformedSecret\"}\n"
                + "Proxy-Authorization: Bearer proxy-secret-token-456\r\n";

        String redactedMalformed = LogResponseMapper.redactSensitiveBody(multiLineMalformed);
        assertThat(redactedMalformed)
                .doesNotContain("unclosedLine1Secret")
                .doesNotContain("line2Secret")
                .doesNotContain("schemaMalformedSecret")
                .doesNotContain("proxy-secret-token-456")
                .contains("Proxy-Authorization: [REDACTED]\r\n");

        String schemaAndSubPathJson = """
                {
                  "urn:ietf:params:scim:schemas:core:2.0:User:password": "SchemaQualifiedPass!",
                  "Operations": [
                    {"op": "replace", "path": "password.value", "value": "DotValuePass!"},
                    {"op": "replace", "path": "password[primary eq true]", "value": "FilteredPass!"}
                  ]
                }
                """;

        assertThat(LogResponseMapper.redactSensitiveBody(schemaAndSubPathJson))
                .doesNotContain("SchemaQualifiedPass!")
                .doesNotContain("DotValuePass!")
                .doesNotContain("FilteredPass!");
    }

    @Test
    void redactSensitiveBodyRedactsBase64UrlTokensWithLeadingOrTrailingNonAlphanumericChars() {
        String repeatedSegment = "9fA7bC3d".repeat(10);
        String dashStartWsToken = "-" + repeatedSegment + "E5gH-";
        String underscoreStartWsToken = "_" + repeatedSegment + "E5gH_";
        String jwtHeader = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS384\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String jwtPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"user-123\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String jwtEndingInDash = jwtHeader + "." + jwtPayload + ".sigPartEndingWithDash-";
        String shortRepeated = "AbCd1234".repeat(4);
        String tokenEndingInPlus = shortRepeated + "+";
        String tokenEndingInSlash = shortRepeated + "/";
        String tokenEndingInTilde = shortRepeated + "~";
        String tokenEndingInEquals = "AbCd1234".repeat(3) + "==";

        String payload = "WsDash: Bearer " + dashStartWsToken + "\n"
                + "WsUnderscore: Bearer " + underscoreStartWsToken + "\n"
                + "JwtDash: Bearer " + jwtEndingInDash + "\n"
                + "B64Plus: Bearer " + tokenEndingInPlus + "\n"
                + "B64Slash: Bearer " + tokenEndingInSlash + "\n"
                + "B68Tilde: Bearer " + tokenEndingInTilde + "\n"
                + "B64Padded: Bearer " + tokenEndingInEquals + "\n"
                + "BareDashes: Bearer ---\n"
                + "BareUnderscores: Bearer _____\n"
                + "Prose: OAuth Bearer Token\n";

        String redacted = LogResponseMapper.redactSensitiveBody(payload);

        assertThat(redacted)
                .contains("WsDash: Bearer [REDACTED]\n")
                .contains("WsUnderscore: Bearer [REDACTED]\n")
                .contains("JwtDash: Bearer [REDACTED]\n")
                .contains("B64Plus: Bearer [REDACTED]\n")
                .contains("B64Slash: Bearer [REDACTED]\n")
                .contains("B68Tilde: Bearer [REDACTED]\n")
                .contains("B64Padded: Bearer [REDACTED]\n")
                .contains("BareDashes: Bearer ---\n")
                .contains("BareUnderscores: Bearer _____\n")
                .contains("Prose: OAuth Bearer Token\n")
                .doesNotContain(dashStartWsToken)
                .doesNotContain(underscoreStartWsToken)
                .doesNotContain(jwtEndingInDash)
                .doesNotContain(tokenEndingInPlus)
                .doesNotContain(tokenEndingInSlash)
                .doesNotContain(tokenEndingInTilde)
                .doesNotContain(tokenEndingInEquals);
    }

    @Test
    void redactSensitiveBodyRedactsCredentialsAfterAdjacentSchemeWords() {
        String plain = "DoubleBearer: Bearer Bearer secret-token-123\n"
                + "BasicThenBearer: Basic Bearer _wsTokenStartingWithUnderscore987\n"
                + "BearerThenBasic: Bearer Basic dXNlcjpwYXNz\n"
                + "DoubleBasic: Basic Basic dXNlcjpwYXNz\n";

        String redactedPlain = LogResponseMapper.redactSensitiveBody(plain);
        assertThat(redactedPlain)
                .contains("DoubleBearer: Bearer Bearer [REDACTED]\n")
                .contains("BasicThenBearer: Basic Bearer [REDACTED]\n")
                .contains("BearerThenBasic: Bearer Basic [REDACTED]\n")
                .contains("DoubleBasic: Basic Basic [REDACTED]\n")
                .doesNotContain("secret-token-123")
                .doesNotContain("_wsTokenStartingWithUnderscore987")
                .doesNotContain("dXNlcjpwYXNz");

        String json = "{\"note\":\"Bearer Bearer -wsTokenStartingWithDash12345\"}";
        assertThat(LogResponseMapper.redactSensitiveBody(json))
                .contains("Bearer Bearer [REDACTED]")
                .doesNotContain("-wsTokenStartingWithDash12345");
    }

    @Test
    void redactSensitiveBodyRedactsMalformedAndTruncatedPatchPasswordOperationsRegardlessOfKeyOrder() {
        String truncatedPatch = """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    {"path": "password", "op": "replace", "value": "SecretWithInterveningOp!"},
                    {"op": "replace", "value": "SecretBeforePath!", "path": "urn:ietf:params:scim:schemas:core:2.0:User:password"},
                    {"op": "replace", "value": "Basic Users", "path": "displayName"},
                    {"op": "replace", "value": {"password": "NestedMalformedSecret!"}},
                    {"op": "replace", "path": "password.value", "value": "TruncatedAtEofSecret""";

        String redacted = LogResponseMapper.redactSensitiveBody(truncatedPatch);

        assertThat(redacted)
                .contains("\"Basic Users\"")
                .doesNotContain("SecretWithInterveningOp!")
                .doesNotContain("SecretBeforePath!")
                .doesNotContain("NestedMalformedSecret!")
                .doesNotContain("TruncatedAtEofSecret");

        String truncatedUnclosedObjectValueFirst =
                "{\"Operations\":[{\"op\":\"replace\",\"value\":\"UnclosedObjectSecret!\",\"path\":\"password[primary eq true]\"";
        assertThat(LogResponseMapper.redactSensitiveBody(truncatedUnclosedObjectValueFirst))
                .contains("\"value\":\"[REDACTED]\"")
                .doesNotContain("UnclosedObjectSecret!");
    }
}
