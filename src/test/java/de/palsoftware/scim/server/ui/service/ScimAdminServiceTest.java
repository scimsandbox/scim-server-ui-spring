package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.ui.repository.ScimGroupRepository;
import de.palsoftware.scim.server.ui.repository.ScimUserRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceRepository;
import de.palsoftware.scim.server.ui.dto.GroupUpsertRequest;
import de.palsoftware.scim.server.ui.dto.UserUpsertRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimAdminServiceTest {

    @Mock
    private WorkspaceRepository workspaceRepository;
    @Mock
    private ScimUserRepository userRepository;
    @Mock
    private ScimGroupRepository groupRepository;
    @Mock
    private ScimGroupMembershipRepository membershipRepository;

    @InjectMocks
    private ScimAdminService service;

    private final UUID workspaceId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private final UUID groupId = UUID.randomUUID();
    private Workspace workspace;

    @BeforeEach
    void setUp() {
        workspace = new Workspace();
        workspace.setId(workspaceId);
        workspace.setCreatedByUsername("owner");
    }

    // ─── listUsers / listUsersPage ──────────────────────────────────────

    @Test
    void listUsers_admin_returnsUsers() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        ScimUser user = buildUser("alice");
        when(userRepository.findByWorkspaceId(workspaceId)).thenReturn(List.of(user));

        List<ScimUser> result = service.listUsers(workspaceId, "admin", true);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getUserName()).isEqualTo("alice");
    }

    @Test
    void listUsers_nonAdmin_checkOwnership() {
        when(workspaceRepository.findByIdAndCreatedByUsername(workspaceId, "owner"))
                .thenReturn(Optional.of(workspace));
        when(userRepository.findByWorkspaceId(workspaceId)).thenReturn(Collections.emptyList());

        List<ScimUser> result = service.listUsers(workspaceId, "owner", false);

        assertThat(result).isEmpty();
    }

    @Test
    void listUsers_nonAdmin_wrongOwner_throws() {
        when(workspaceRepository.findByIdAndCreatedByUsername(workspaceId, "other"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.listUsers(workspaceId, "other", false))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void listUsersPage_withQuery_filtersUsers() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        PageRequest pageable = PageRequest.of(0, 20);
        when(userRepository.findByWorkspaceIdAndUserNameContainingIgnoreCase(workspaceId, "ali", pageable))
                .thenReturn(new PageImpl<>(List.of(buildUser("alice"))));

        Page<ScimUser> result = service.listUsersPage(workspaceId, "ali", pageable, "admin", true);

        assertThat(result.getTotalElements()).isEqualTo(1);
    }

    @Test
    void listUsersPage_noQuery_returnsAll() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        PageRequest pageable = PageRequest.of(0, 20);
        when(userRepository.findByWorkspaceId(workspaceId, pageable))
                .thenReturn(new PageImpl<>(Collections.emptyList()));

        Page<ScimUser> result = service.listUsersPage(workspaceId, null, pageable, "admin", true);

        assertThat(result.getTotalElements()).isZero();
    }

    // ─── createUser ─────────────────────────────────────────────────────

    @Test
    void createUser_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> {
            ScimUser u = i.getArgument(0);
            u.setId(userId);
            return u;
        });

        ScimUser result = service.createUser(workspaceId, buildUserRequest("newuser"), "admin", true);

        assertThat(result.getUserName()).isEqualTo("newuser");
        verify(userRepository).save(any(ScimUser.class));
    }

    @Test
    void createUser_duplicate_throwsConflict() {
        when(userRepository.existsByUserNameIgnoreCaseAndWorkspaceId("existing", workspaceId))
                .thenReturn(true);

        UserUpsertRequest request = buildUserRequest("existing");

        assertThatThrownBy(() -> service.createUser(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("already exists");
    }

    @Test
    void createUser_missingUserName_throwsBadRequest() {
        UserUpsertRequest request = buildUserRequest("");

        assertThatThrownBy(() -> service.createUser(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    // ─── updateUser ─────────────────────────────────────────────────────

    @Test
    void updateUser_success() {
        ScimUser existing = buildUser("old");
        existing.setId(userId);
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> i.getArgument(0));

        ScimUser result = service.updateUser(workspaceId, userId, buildUserRequest("newname"), "admin", true);

        assertThat(result.getUserName()).isEqualTo("newname");
    }

    @Test
    void updateUser_conflictUserName_throws() {
        ScimUser existing = buildUser("old");
        existing.setId(userId);
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));
        when(userRepository.existsByUserNameIgnoreCaseAndWorkspaceId("taken", workspaceId)).thenReturn(true);

        UserUpsertRequest request = buildUserRequest("taken");

        assertThatThrownBy(() -> service.updateUser(workspaceId, userId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    // ─── deleteUser ─────────────────────────────────────────────────────

    @Test
    void deleteUser_success() {
        ScimUser existing = buildUser("alice");
        existing.setId(userId);
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));

        service.deleteUser(workspaceId, userId, "admin", true);

        verify(membershipRepository).deleteByMemberValue(userId);
        verify(userRepository).delete(existing);
    }

    @Test
    void deleteUser_notFound_throws() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteUser(workspaceId, userId, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    // ─── deleteAllUsers ─────────────────────────────────────────────────

    @Test
    void deleteAllUsers_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findIdsByWorkspaceId(workspaceId)).thenReturn(List.of(userId));

        service.deleteAllUsers(workspaceId, "admin", true);

        verify(membershipRepository).deleteByMemberValueIn(List.of(userId));
        verify(userRepository).deleteAllByWorkspaceId(workspaceId);
    }

    // ─── Groups ─────────────────────────────────────────────────────────

    @Test
    void createGroup_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> {
            ScimGroup g = i.getArgument(0);
            g.setId(groupId);
            return g;
        });

        ScimGroup result = service.createGroup(workspaceId,
                new GroupUpsertRequest("Team A", "EXT-1", null), "admin", true);

        assertThat(result.getDisplayName()).isEqualTo("Team A");
    }

    @Test
    void createGroup_duplicate_throwsConflict() {
        when(groupRepository.existsByDisplayNameAndWorkspaceId("Team A", workspaceId)).thenReturn(true);

        GroupUpsertRequest request = new GroupUpsertRequest("Team A", null, null);

        assertThatThrownBy(() -> service.createGroup(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void deleteGroup_success() {
        ScimGroup group = new ScimGroup();
        group.setId(groupId);
        group.setDisplayName("Team A");
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        service.deleteGroup(workspaceId, groupId, "admin", true);

        verify(membershipRepository).deleteByMemberValue(groupId);
        verify(membershipRepository).deleteByGroupId(groupId);
        verify(groupRepository).delete(group);
    }

    @Test
    void deleteAllGroups_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.findIdsByWorkspaceId(workspaceId)).thenReturn(List.of(groupId));

        service.deleteAllGroups(workspaceId, "admin", true);

        verify(membershipRepository).deleteByMemberValueIn(List.of(groupId));
        verify(membershipRepository).deleteByGroupIdIn(List.of(groupId));
        verify(groupRepository).deleteAllByWorkspaceId(workspaceId);
    }

    @Test
    void listGroupsPage_withQuery_filtersGroups() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        PageRequest pageable = PageRequest.of(0, 20);
        when(groupRepository.findByWorkspaceIdAndDisplayNameContainingIgnoreCaseOrWorkspaceIdAndExternalIdContainingIgnoreCase(
            workspaceId, "team", workspaceId, "team", pageable))
                .thenReturn(new PageImpl<>(Collections.emptyList()));

        Page<ScimGroup> result = service.listGroupsPage(workspaceId, "team", pageable, "admin", true);

        assertThat(result.getTotalElements()).isZero();
    }

    // ─── helpers ────────────────────────────────────────────────────────

    private ScimUser buildUser(String userName) {
        ScimUser user = new ScimUser();
        user.setUserName(userName);
        user.setWorkspace(workspace);
        return user;
    }

    private UserUpsertRequest buildUserRequest(String userName) {
        return new UserUpsertRequest(
                userName, "Display", true, null,
                null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null);
    }
}
