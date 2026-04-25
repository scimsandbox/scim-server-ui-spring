package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.Workspace;

import de.palsoftware.scim.server.ui.repository.WorkspaceDataStats;
import de.palsoftware.scim.server.ui.dto.GenerateDataRequest;
import de.palsoftware.scim.server.ui.service.DataGeneratorService;
import de.palsoftware.scim.server.ui.repository.MgmtUserRepository;
import de.palsoftware.scim.server.ui.service.WorkspaceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WorkspaceManagementControllerTest {

    @Mock
    private WorkspaceService workspaceService;
    @Mock
    private DataGeneratorService generatorService;
    @Mock
    private MgmtUserRepository mgmtUserRepository;

    @InjectMocks
    private ApiWorkspacesController controller;

    private final UUID workspaceId = UUID.randomUUID();
    private Authentication auth;

    @BeforeEach
    void setUp() {
        auth = mock(Authentication.class);
        org.mockito.Mockito.lenient().when(auth.getPrincipal()).thenReturn(null);
        org.mockito.Mockito.lenient().when(auth.getName()).thenReturn("user@test.com");
        org.mockito.Mockito.lenient().when(auth.getAuthorities()).thenAnswer(inv -> java.util.List
                .of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void listWorkspaces_returnsOk() {
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        when(workspaceService.listWorkspaces("user@test.com", true)).thenReturn(List.of(ws));

        ResponseEntity<List<Map<String, Object>>> response = controller.listWorkspaces(auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
    }

    @Test
    void getWorkspace_found_returnsOk() {
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        when(workspaceService.getWorkspace(workspaceId, "user@test.com", true))
                .thenReturn(Optional.of(ws));
        WorkspaceDataStats stats = new WorkspaceDataStats(10, 5, 2, 100, 50, 30, 10, 5, 3, 2, 1, 0, 20, 4096);
        when(workspaceService.getWorkspaceDataStats(workspaceId, "user@test.com", true)).thenReturn(stats);

        ResponseEntity<Map<String, Object>> response = controller.getWorkspace(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void getWorkspace_notFound_returns404() {

        when(workspaceService.getWorkspace(workspaceId, "user@test.com", true))
                .thenReturn(Optional.empty());

        ResponseEntity<Map<String, Object>> response = controller.getWorkspace(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void createWorkspace_returnsCreated() {
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        when(workspaceService.createWorkspace("WS", "desc", "user@test.com")).thenReturn(ws);

        ResponseEntity<Map<String, Object>> response = controller
                .createWorkspace(Map.of("name", "WS", "description", "desc"), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void deleteWorkspace_returnsNoContent() {

        ResponseEntity<Void> response = controller.deleteWorkspace(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(workspaceService).deleteWorkspace(workspaceId, "user@test.com", true);
    }

    @Test
    void getWorkspaceStats_returnsOk() {
        WorkspaceDataStats stats = new WorkspaceDataStats(10, 5, 2, 100, 50, 30, 10, 5, 3, 2, 1, 0, 20, 4096);

        when(workspaceService.getWorkspaceDataStats(workspaceId, "user@test.com", true)).thenReturn(stats);

        ResponseEntity<Map<String, Object>> response = controller.getWorkspaceStats(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void generateData_returnsOk() {

        DataGeneratorService.GenerationSummary summary = new DataGeneratorService.GenerationSummary(10, 10, 10, 0, 0);
        when(generatorService.generateUsers(any(), any(), anyString(), anyBoolean())).thenReturn(summary);

        ResponseEntity<Map<String, Object>> response = controller.generateData(
                workspaceId.toString(), "users", new GenerateDataRequest(10), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
