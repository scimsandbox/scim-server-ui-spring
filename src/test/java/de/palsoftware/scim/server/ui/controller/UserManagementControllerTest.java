package de.palsoftware.scim.server.ui.controller;

import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.dto.UserUpsertRequest;
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
class UserManagementControllerTest {

    @Mock private ScimAdminService scimAdminService;

    @Mock private WorkspaceService workspaceService;

    @InjectMocks
    private ApiUsersController controller;

    private final UUID workspaceId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private Authentication auth;

    @BeforeEach
    void setUp() {
                auth = mock(Authentication.class);
        org.mockito.Mockito.lenient().when(auth.getPrincipal()).thenReturn(null);
        org.mockito.Mockito.lenient().when(auth.getName()).thenReturn("user@test.com");
        org.mockito.Mockito.lenient().when(auth.getAuthorities()).thenAnswer(inv -> java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void listUsers_returnsOk() {
        
        when(scimAdminService.listUsersPage(any(UUID.class), any(), any(PageRequest.class), anyString(), anyBoolean()))
                .thenReturn(new PageImpl<>(Collections.emptyList()));


        ResponseEntity<Map<String, Object>> response =
                controller.listUsers(workspaceId.toString(), 1, 20, null, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("items");
    }

    @Test
    void lookupUsers_returnsOk() {
        ScimUser user = new ScimUser();
        user.setId(userId);
        user.setUserName("alice");
        
        when(scimAdminService.listUsersPage(any(UUID.class), any(), any(PageRequest.class), anyString(), anyBoolean()))
                .thenReturn(new PageImpl<>(List.of(user)));


        ResponseEntity<List<Map<String, Object>>> response =
                controller.lookupUsers(workspaceId.toString(), "ali", 50, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
    }

    @Test
    void createUser_returns201() {
        ScimUser created = new ScimUser();
        created.setId(userId);
        created.setUserName("newuser");
        
        when(scimAdminService.createUser(any(UUID.class), any(UserUpsertRequest.class), anyString(), anyBoolean()))
                .thenReturn(created);


        UserUpsertRequest request = new UserUpsertRequest(
                "newuser", "Display", true, null,
                null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null);

        ResponseEntity<Map<String, Object>> response =
                controller.createUser(workspaceId.toString(), request, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).containsEntry("userName", "newuser");
    }

    @Test
    void updateUser_returnsOk() {
        ScimUser updated = new ScimUser();
        updated.setId(userId);
        
        when(scimAdminService.updateUser(any(UUID.class), any(UUID.class), any(UserUpsertRequest.class), anyString(), anyBoolean()))
                .thenReturn(updated);


        UserUpsertRequest request = new UserUpsertRequest(
                "updated", "Display", true, null,
                null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null);

        ResponseEntity<Map<String, Object>> response =
                controller.updateUser(workspaceId.toString(), userId.toString(), request, auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void deleteUser_returnsNoContent() {
        

        ResponseEntity<Void> response =
                controller.deleteUser(workspaceId.toString(), userId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(scimAdminService).deleteUser(workspaceId, userId, "user@test.com", true);
    }

    @Test
    void clearUsers_returnsNoContent() {
        

        ResponseEntity<Void> response = controller.clearUsers(workspaceId.toString(), auth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(scimAdminService).deleteAllUsers(workspaceId, "user@test.com", true);
    }
}
