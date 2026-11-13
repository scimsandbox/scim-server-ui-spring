package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.dto.GroupUpsertRequest;
import de.palsoftware.scim.server.ui.dto.UserUpsertRequest;
import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.ui.repository.ScimGroupRepository;
import de.palsoftware.scim.server.ui.repository.ScimUserRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimAdminServiceTest {

    private static final String BCRYPT_REGEX = "^\\$2[aby]\\$[0-9]{2}\\$.{53}$";

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

    // ─── createUser & Authorization Ordering ────────────────────────────

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
        assertThat(result.getPassword()).isNull();
        verify(userRepository).save(any(ScimUser.class));
    }

    @Test
    void createUser_unauthorizedWorkspace_checksAccessBeforeUserExistenceLookup() {
        when(workspaceRepository.findByIdAndCreatedByUsername(workspaceId, "intruder"))
                .thenReturn(Optional.empty());
        UserUpsertRequest request = buildUserRequest("existing");

        assertThatThrownBy(() -> service.createUser(workspaceId, request, "intruder", false))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND));

        verifyNoInteractions(userRepository);
    }

    @Test
    void createUser_duplicate_throwsConflict() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.existsByUserNameIgnoreCaseAndWorkspaceId("existing", workspaceId))
                .thenReturn(true);

        UserUpsertRequest request = buildUserRequest("existing");

        assertThatThrownBy(() -> service.createUser(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("already exists");
    }

    @Test
    void createUser_missingUserName_throwsBadRequest() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        UserUpsertRequest request = buildUserRequest("");

        assertThatThrownBy(() -> service.createUser(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    // ─── BCrypt Password Hashing & >72-byte Rejection ───────────────────

    @Test
    void createUser_withPassword_storesBcryptHashAndNeverPlaintext() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> i.getArgument(0));

        ScimUser result = service.createUser(
                workspaceId,
                buildUserRequestWithPassword("alice", "S3cretP@ssw0rd!"),
                "admin",
                true);

        assertThat(result.getPassword())
                .isNotNull()
                .doesNotContain("S3cretP@ssw0rd!")
                .matches(BCRYPT_REGEX);
        assertThat(new BCryptPasswordEncoder().matches("S3cretP@ssw0rd!", result.getPassword())).isTrue();
    }

    @Test
    void createUser_passwordOver72Utf8Bytes_throwsBadRequest() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        // 25 3-byte UTF-8 characters = 75 bytes (> 72 UTF-8 byte BCrypt limit despite length 25)
        String multiBytePassword = "€".repeat(25);
        UserUpsertRequest request = buildUserRequestWithPassword("alice", multiBytePassword);

        assertThatThrownBy(() -> service.createUser(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .hasMessageContaining("72 UTF-8 bytes");
    }

    @Test
    void updateUser_blankPassword_preservesExistingBcryptHash() {
        ScimUser existing = buildUser("alice");
        existing.setId(userId);
        String existingHash = new BCryptPasswordEncoder().encode("InitialPass123!");
        existing.setPassword(existingHash);

        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> i.getArgument(0));

        ScimUser result = service.updateUser(
                workspaceId,
                userId,
                buildUserRequestWithPassword("alice", "   "),
                "admin",
                true);

        assertThat(result.getPassword()).isEqualTo(existingHash);
    }

    @Test
    void updateUser_newPassword_replacesWithNewBcryptHashAndRejectsOver72Bytes() {
        ScimUser existing = buildUser("alice");
        existing.setId(userId);
        existing.setPassword(new BCryptPasswordEncoder().encode("OldPass123!"));

        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> i.getArgument(0));

        ScimUser updated = service.updateUser(
                workspaceId,
                userId,
                buildUserRequestWithPassword("alice", "UpdatedPass456!"),
                "admin",
                true);

        assertThat(updated.getPassword()).matches(BCRYPT_REGEX);
        assertThat(new BCryptPasswordEncoder().matches("UpdatedPass456!", updated.getPassword())).isTrue();

        UserUpsertRequest tooLong = buildUserRequestWithPassword("alice", "a".repeat(73));
        assertThatThrownBy(() -> service.updateUser(workspaceId, userId, tooLong, "admin", true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));
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

    @Test
    void updateUser_nullCollections_success() {
        ScimUser existing = buildUser("old");
        existing.setId(userId);
        existing.setEmails(null);
        existing.setPhoneNumbers(null);
        existing.setAddresses(null);
        existing.setEntitlements(null);
        existing.setRoles(null);
        existing.setIms(null);
        existing.setPhotos(null);
        existing.setX509Certificates(null);

        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> i.getArgument(0));

        UserUpsertRequest request = new UserUpsertRequest(
                "newname", "Display", true, null,
                null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null,
                List.of(new UserUpsertRequest.MultiValue("123-456", "work", "Work Phone", true)),
                null, null, null, null, null, null);

        ScimUser result = service.updateUser(workspaceId, userId, request, "admin", true);

        assertThat(result.getUserName()).isEqualTo("newname");
        assertThat(result.getPhoneNumbers()).hasSize(1);
        assertThat(result.getPhoneNumbers().get(0).getValue()).isEqualTo("123-456");
    }

    // ─── deleteUser / deleteAllUsers ────────────────────────────────────

    @Test
    void deleteUser_success() {
        ScimUser existing = buildUser("alice");
        existing.setId(userId);
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(existing));

        service.deleteUser(workspaceId, userId, "admin", true);

        verify(membershipRepository).deleteByWorkspaceIdAndMemberValue(workspaceId, userId);
        verify(userRepository).delete(existing);
    }

    @Test
    void deleteUser_notFound_throws() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteUser(workspaceId, userId, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void deleteAllUsers_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findIdsByWorkspaceId(workspaceId)).thenReturn(List.of(userId));

        service.deleteAllUsers(workspaceId, "admin", true);

        verify(membershipRepository).deleteByWorkspaceIdAndMemberValueIn(workspaceId, List.of(userId));
        verify(userRepository).deleteAllByWorkspaceId(workspaceId);
    }

    // ─── Groups & Scoped Membership Enforcement ─────────────────────────

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
    void createGroup_unauthorizedWorkspace_checksAccessBeforeGroupExistenceLookup() {
        when(workspaceRepository.findByIdAndCreatedByUsername(workspaceId, "intruder"))
                .thenReturn(Optional.empty());
        GroupUpsertRequest request = new GroupUpsertRequest("Team A", null, null);

        assertThatThrownBy(() -> service.createGroup(workspaceId, request, "intruder", false))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND));

        verifyNoInteractions(groupRepository);
    }

    @Test
    void createGroup_duplicate_throwsConflict() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.existsByDisplayNameAndWorkspaceId("Team A", workspaceId)).thenReturn(true);

        GroupUpsertRequest request = new GroupUpsertRequest("Team A", null, null);

        assertThatThrownBy(() -> service.createGroup(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void createGroup_crossWorkspaceUserMember_throwsBadRequest() {
        UUID foreignUserId = UUID.randomUUID();
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.existsByIdAndWorkspaceId(foreignUserId, workspaceId)).thenReturn(false);

        GroupUpsertRequest request = new GroupUpsertRequest(
                "Team A",
                null,
                List.of(new GroupUpsertRequest.Member(foreignUserId.toString(), "User", "Foreign User")));

        assertThatThrownBy(() -> service.createGroup(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .hasMessageContaining("does not exist in workspace");
    }

    @Test
    void createGroup_crossWorkspaceGroupMember_throwsBadRequest() {
        UUID foreignGroupId = UUID.randomUUID();
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.existsByIdAndWorkspaceId(foreignGroupId, workspaceId)).thenReturn(false);

        GroupUpsertRequest request = new GroupUpsertRequest(
                "Team A",
                null,
                List.of(new GroupUpsertRequest.Member(foreignGroupId.toString(), "Group", "Foreign Group")));

        assertThatThrownBy(() -> service.createGroup(workspaceId, request, "admin", true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .hasMessageContaining("does not exist in workspace");
    }

    @Test
    void createGroup_sameWorkspaceMembers_succeedsAndDeduplicates() {
        UUID nestedGroupId = UUID.randomUUID();
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.existsByIdAndWorkspaceId(userId, workspaceId)).thenReturn(true);
        when(groupRepository.existsByIdAndWorkspaceId(nestedGroupId, workspaceId)).thenReturn(true);
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> i.getArgument(0));

        GroupUpsertRequest request = new GroupUpsertRequest(
                "Team A",
                "EXT-1",
                List.of(
                        new GroupUpsertRequest.Member(userId.toString(), "user", "Alice"),
                        new GroupUpsertRequest.Member(userId.toString(), "User", "Alice Duplicate"),
                        new GroupUpsertRequest.Member(nestedGroupId.toString(), "group", "Subteam")));

        ScimGroup saved = service.createGroup(workspaceId, request, "admin", true);

        assertThat(saved.getMembers()).hasSize(2);
        assertThat(saved.getMembers().get(0).getWorkspaceId()).isEqualTo(workspaceId);
        assertThat(saved.getMembers().get(0).getMemberType()).isEqualTo("User");
        assertThat(saved.getMembers().get(1).getMemberType()).isEqualTo("Group");
    }

    @Test
    void deleteGroup_success() {
        ScimGroup group = new ScimGroup();
        group.setId(groupId);
        group.setWorkspace(workspace);
        group.setDisplayName("Team A");
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        service.deleteGroup(workspaceId, groupId, "admin", true);

        verify(membershipRepository).deleteByWorkspaceIdAndMemberValue(workspaceId, groupId);
        verify(membershipRepository).deleteByWorkspaceIdAndGroupId(workspaceId, groupId);
        verify(groupRepository).delete(group);
    }

    @Test
    void deleteAllGroups_success() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.findIdsByWorkspaceId(workspaceId)).thenReturn(List.of(groupId));

        service.deleteAllGroups(workspaceId, "admin", true);

        verify(membershipRepository).deleteByWorkspaceIdAndMemberValueIn(workspaceId, List.of(groupId));
        verify(membershipRepository).deleteByWorkspaceIdAndGroupIdIn(workspaceId, List.of(groupId));
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
        return buildUserRequestWithPassword(userName, null);
    }

    private UserUpsertRequest buildUserRequestWithPassword(String userName, String password) {
        return new UserUpsertRequest(
                userName, "Display", true, null,
                null, null, null, null, null, null,
                null, null, null, null, null, null, null, password,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null);
    }
}
