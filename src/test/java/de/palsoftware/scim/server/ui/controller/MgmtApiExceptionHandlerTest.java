package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.security.InvalidAuthenticatedPrincipalException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MgmtApiExceptionHandlerTest {

    private final MgmtApiExceptionHandler handler = new MgmtApiExceptionHandler();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void handleResponseStatusReturnsStructuredPayload() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/workspaces/bad/users");

        ResponseEntity<Map<String, Object>> response = handler.handleResponseStatus(
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Workspace not found"),
                request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody())
                .containsEntry("status", 404)
                .containsEntry("error", "Not Found")
                .containsEntry("message", "Workspace not found")
                .containsEntry("path", "/api/workspaces/bad/users");
    }

    @Test
    void handleIllegalArgumentReturnsBadRequestPayload() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/workspaces/not-a-uuid");

        ResponseEntity<Map<String, Object>> response = handler.handleIllegalArgument(
                new IllegalArgumentException("Invalid UUID string: not-a-uuid"),
                request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody())
                .containsEntry("status", 400)
                .containsEntry("error", "Bad Request")
                .containsEntry("message", "Invalid UUID string: not-a-uuid")
                .containsEntry("path", "/api/workspaces/not-a-uuid");
    }

    @Test
    void handleInvalidPrincipalReturns401InvalidatesSessionAndClearsSecurityContext() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/workspaces");
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        "stale-principal",
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))));

        ResponseEntity<Map<String, Object>> response = handler.handleInvalidPrincipal(
                new InvalidAuthenticatedPrincipalException("Authenticated principal is missing a verified email address"),
                request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(session.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getBody())
                .containsEntry("status", 401)
                .containsEntry("error", "Unauthorized")
                .containsEntry("path", "/api/workspaces");
    }
}