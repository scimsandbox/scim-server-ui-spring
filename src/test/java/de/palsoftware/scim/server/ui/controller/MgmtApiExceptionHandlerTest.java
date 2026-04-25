package de.palsoftware.scim.server.ui.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MgmtApiExceptionHandlerTest {

    private final MgmtApiExceptionHandler handler = new MgmtApiExceptionHandler();

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
}