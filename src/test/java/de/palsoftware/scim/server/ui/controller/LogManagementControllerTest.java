package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.service.LogService;
import de.palsoftware.scim.server.ui.service.WorkspaceService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LogManagementControllerTest {

    @Mock private LogService logService;

    @Mock private WorkspaceService workspaceService;

    @InjectMocks
    private ApiLogsController controller;

    private final UUID workspaceId = UUID.randomUUID();
    private Authentication auth;

    @BeforeEach
    void setUp() {
                auth = mock(Authentication.class);
        org.mockito.Mockito.lenient().when(auth.getPrincipal()).thenReturn(null);
        org.mockito.Mockito.lenient().when(auth.getName()).thenReturn("user@test.com");
        org.mockito.Mockito.lenient().when(auth.getAuthorities()).thenAnswer(inv -> java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void listLogs_returnsOk() {
        
        when(workspaceService.requireWorkspaceId(workspaceId.toString(), "user@test.com", true)).thenReturn(workspaceId);
        when(logService.listLogs(any(UUID.class), any())).thenReturn(new PageImpl<>(Collections.emptyList()));


        ResponseEntity<Map<String, Object>> response =
                controller.listLogs(workspaceId.toString(), 1, 20, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void clearLogs_returnsNoContent() {
        
        when(workspaceService.requireWorkspaceId(workspaceId.toString(), "user@test.com", true)).thenReturn(workspaceId);

        ResponseEntity<Void> response = controller.clearLogs(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(logService).clearLogs(workspaceId);
    }
}
