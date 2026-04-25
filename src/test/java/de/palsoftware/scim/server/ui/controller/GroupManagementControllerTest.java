package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.dto.GroupUpsertRequest;
import de.palsoftware.scim.server.ui.service.WorkspaceService;

import de.palsoftware.scim.server.ui.service.ScimAdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GroupManagementControllerTest {

    @Mock private ScimAdminService scimAdminService;

    @Mock private WorkspaceService workspaceService;

    @InjectMocks
    private ApiGroupsController controller;

    private final UUID workspaceId = UUID.randomUUID();
    private final UUID groupId = UUID.randomUUID();
    private Authentication auth;

    @BeforeEach
    void setUp() {
                auth = mock(Authentication.class);
        org.mockito.Mockito.lenient().when(auth.getPrincipal()).thenReturn(null);
        org.mockito.Mockito.lenient().when(auth.getName()).thenReturn("user@test.com");
        org.mockito.Mockito.lenient().when(auth.getAuthorities()).thenAnswer(inv -> java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void listGroups_returnsOk() {
        
        when(scimAdminService.listGroupsPage(any(UUID.class), any(), any(PageRequest.class), anyString(), anyBoolean()))
                .thenReturn(new PageImpl<>(Collections.emptyList()));


        ResponseEntity<Map<String, Object>> response =
                controller.listGroups(workspaceId.toString(), 1, 20, null, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void lookupGroups_returnsOk() {
        ScimGroup group = new ScimGroup();
        group.setId(groupId);
        group.setDisplayName("Team A");
        
        when(scimAdminService.listGroupsPage(any(UUID.class), any(), any(PageRequest.class), anyString(), anyBoolean()))
                .thenReturn(new PageImpl<>(List.of(group)));


        ResponseEntity<List<Map<String, Object>>> response =
                controller.lookupGroups(workspaceId.toString(), "team", 50, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
    }

    @Test
    void createGroup_returns201() {
        ScimGroup created = new ScimGroup();
        created.setId(groupId);
        created.setDisplayName("Team B");
        
        when(scimAdminService.createGroup(any(UUID.class), any(GroupUpsertRequest.class), anyString(), anyBoolean()))
                .thenReturn(created);


        GroupUpsertRequest request = new GroupUpsertRequest("Team B", null, null);

        ResponseEntity<Map<String, Object>> response =
                controller.createGroup(workspaceId.toString(), request, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void updateGroup_returnsOk() {
        ScimGroup updated = new ScimGroup();
        updated.setId(groupId);
        
        when(scimAdminService.updateGroup(any(UUID.class), any(UUID.class), any(GroupUpsertRequest.class), anyString(), anyBoolean()))
                .thenReturn(updated);


        GroupUpsertRequest request = new GroupUpsertRequest("Updated", null, null);

        ResponseEntity<Map<String, Object>> response =
                controller.updateGroup(workspaceId.toString(), groupId.toString(), request, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void deleteGroup_returnsNoContent() {
        

        ResponseEntity<Void> response =
                controller.deleteGroup(workspaceId.toString(), groupId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(scimAdminService).deleteGroup(workspaceId, groupId, "user@test.com", true);
    }

    @Test
    void clearGroups_returnsNoContent() {
        

        ResponseEntity<Void> response = controller.clearGroups(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(scimAdminService).deleteAllGroups(workspaceId, "user@test.com", true);
    }
}
