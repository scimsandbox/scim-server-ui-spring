package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.dto.GroupUpsertRequest;
import de.palsoftware.scim.server.ui.dto.UserUpsertRequest;
import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.model.ScimGroupMembership;
import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.model.ScimUserAddress;
import de.palsoftware.scim.server.ui.model.ScimUserEmail;
import de.palsoftware.scim.server.ui.model.ScimUserEntitlement;
import de.palsoftware.scim.server.ui.model.ScimUserIm;
import de.palsoftware.scim.server.ui.model.ScimUserPhoneNumber;
import de.palsoftware.scim.server.ui.model.ScimUserPhoto;
import de.palsoftware.scim.server.ui.model.ScimUserRole;
import de.palsoftware.scim.server.ui.model.ScimUserX509Certificate;
import de.palsoftware.scim.server.ui.model.Workspace;
import de.palsoftware.scim.server.ui.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.ui.repository.ScimGroupRepository;
import de.palsoftware.scim.server.ui.repository.ScimUserRepository;
import de.palsoftware.scim.server.ui.repository.WorkspaceRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.hibernate.Hibernate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

@Service
@Transactional(readOnly = true)
public class ScimAdminService {

    private static final int MAX_BCRYPT_PASSWORD_BYTES = 72;
    private static final String MEMBER_TYPE_USER = "User";
    private static final String MEMBER_TYPE_GROUP = "Group";

    private final WorkspaceRepository workspaceRepository;
    private final ScimUserRepository userRepository;
    private final ScimGroupRepository groupRepository;
    private final ScimGroupMembershipRepository membershipRepository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public ScimAdminService(WorkspaceRepository workspaceRepository,
                             ScimUserRepository userRepository,
                             ScimGroupRepository groupRepository,
                             ScimGroupMembershipRepository membershipRepository) {
        this.workspaceRepository = workspaceRepository;
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
        this.membershipRepository = membershipRepository;
    }

    public List<ScimUser> listUsers(UUID workspaceId, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        return userRepository.findByWorkspaceId(workspaceId).stream()
            .sorted(Comparator.comparing(u -> safeLower(u.getUserName())))
            .toList();
    }

    public Page<ScimUser> listUsersPage(UUID workspaceId, String query, Pageable pageable, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        Page<ScimUser> page;
        if (query == null || query.isBlank()) {
            page = userRepository.findByWorkspaceId(workspaceId, pageable);
        } else {
            page = userRepository.findByWorkspaceIdAndUserNameContainingIgnoreCase(workspaceId, query, pageable);
        }
        return page;
    }

    @Transactional
    public ScimUser createUser(UUID workspaceId, UserUpsertRequest request, String actorUsername, boolean admin) {
        Workspace ws = ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        String userName = normalizeRequired("userName", request.userName());
        if (userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(userName, workspaceId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "User with userName '" + userName + "' already exists");
        }

        ScimUser user = new ScimUser();
        user.setWorkspace(ws);
        user.setUserName(userName);
        applyUserFields(user, request, true);

        return userRepository.save(user);
    }

    @Transactional
    public ScimUser updateUser(UUID workspaceId, UUID userId, UserUpsertRequest request, String actorUsername, boolean admin) {
        ScimUser user = getUser(workspaceId, userId, actorUsername, admin);

        if (request.userName() != null) {
            String userName = normalizeRequired("userName", request.userName());
            if (!user.getUserName().equalsIgnoreCase(userName)
                    && userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(userName, workspaceId)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "User with userName '" + userName + "' already exists");
            }
            user.setUserName(userName);
        }

        applyUserFields(user, request, false);

        return userRepository.save(user);
    }

    @Transactional
    public void deleteUser(UUID workspaceId, UUID userId, String actorUsername, boolean admin) {
        ScimUser user = getUser(workspaceId, userId, actorUsername, admin);
        membershipRepository.deleteByWorkspaceIdAndMemberValue(workspaceId, userId);
        userRepository.delete(user);
    }

    @Transactional
    public void deleteAllUsers(UUID workspaceId, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        List<UUID> userIds = userRepository.findIdsByWorkspaceId(workspaceId);
        if (!userIds.isEmpty()) {
            membershipRepository.deleteByWorkspaceIdAndMemberValueIn(workspaceId, userIds);
            userRepository.deleteAllByWorkspaceId(workspaceId);
        }
    }

    public List<ScimGroup> listGroups(UUID workspaceId, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        List<ScimGroup> groups = groupRepository.findByWorkspaceId(workspaceId).stream()
                .sorted(Comparator.comparing(g -> safeLower(g.getDisplayName())))
                .toList();
        groups.forEach(this::initializeLazyGroupCollections);
        return groups;
    }

    public Page<ScimGroup> listGroupsPage(UUID workspaceId, String query, Pageable pageable, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        Page<ScimGroup> page;
        if (query == null || query.isBlank()) {
            page = groupRepository.findByWorkspaceId(workspaceId, pageable);
        } else {
            page = groupRepository.findByWorkspaceIdAndDisplayNameContainingIgnoreCaseOrWorkspaceIdAndExternalIdContainingIgnoreCase(
                    workspaceId, query, workspaceId, query, pageable);
        }
        page.forEach(this::initializeLazyGroupCollections);
        return page;
    }

    @Transactional
    public ScimGroup createGroup(UUID workspaceId, GroupUpsertRequest request, String actorUsername, boolean admin) {
        Workspace ws = ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        String displayName = normalizeRequired("displayName", request.displayName());
        if (groupRepository.existsByDisplayNameAndWorkspaceId(displayName, workspaceId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Group with displayName '" + displayName + "' already exists");
        }

        ScimGroup group = new ScimGroup();
        group.setWorkspace(ws);
        group.setDisplayName(displayName);
        applyGroupFields(group, request, true);

        ScimGroup saved = groupRepository.save(group);
        initializeLazyGroupCollections(saved);
        return saved;
    }

    @Transactional
    public ScimGroup updateGroup(UUID workspaceId, UUID groupId, GroupUpsertRequest request, String actorUsername, boolean admin) {
        ScimGroup group = getGroup(workspaceId, groupId, actorUsername, admin);

        if (request.displayName() != null) {
            String displayName = normalizeRequired("displayName", request.displayName());
            if (!group.getDisplayName().equals(displayName)
                    && groupRepository.existsByDisplayNameAndWorkspaceId(displayName, workspaceId)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "Group with displayName '" + displayName + "' already exists");
            }
            group.setDisplayName(displayName);
        }

        applyGroupFields(group, request, false);

        ScimGroup saved = groupRepository.save(group);
        initializeLazyGroupCollections(saved);
        return saved;
    }

    @Transactional
    public void deleteGroup(UUID workspaceId, UUID groupId, String actorUsername, boolean admin) {
        ScimGroup group = getGroup(workspaceId, groupId, actorUsername, admin);
        membershipRepository.deleteByWorkspaceIdAndMemberValue(workspaceId, groupId);
        membershipRepository.deleteByWorkspaceIdAndGroupId(workspaceId, groupId);
        groupRepository.delete(group);
    }

    @Transactional
    public void deleteAllGroups(UUID workspaceId, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        List<UUID> groupIds = groupRepository.findIdsByWorkspaceId(workspaceId);
        if (!groupIds.isEmpty()) {
            membershipRepository.deleteByWorkspaceIdAndMemberValueIn(workspaceId, groupIds);
            membershipRepository.deleteByWorkspaceIdAndGroupIdIn(workspaceId, groupIds);
            groupRepository.deleteAllByWorkspaceId(workspaceId);
        }
    }

    private Workspace ensureWorkspaceAccess(UUID workspaceId, String actorUsername, boolean admin) {
        if (admin) {
            return workspaceRepository.findById(workspaceId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Workspace not found"));
        }
        return workspaceRepository.findByIdAndCreatedByUsername(workspaceId, actorUsername)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Workspace not found"));
    }

    private ScimUser getUser(UUID workspaceId, UUID userId, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        return userRepository.findByIdAndWorkspaceId(userId, workspaceId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private ScimGroup getGroup(UUID workspaceId, UUID groupId, String actorUsername, boolean admin) {
        ensureWorkspaceAccess(workspaceId, actorUsername, admin);
        ScimGroup group = groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Group not found"));
        initializeLazyGroupCollections(group);
        return group;
    }

    private String normalizeOptional(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private void applyUserFields(ScimUser user, UserUpsertRequest request, boolean isCreate) {
        applyScalarUserFields(user, request, isCreate);
        if (request.emails() != null) applyEmails(user, request.emails());
        if (request.phoneNumbers() != null) applyPhoneNumbers(user, request.phoneNumbers());
        if (request.addresses() != null) applyAddresses(user, request.addresses());
        if (request.entitlements() != null) applyEntitlements(user, request.entitlements());
        if (request.roles() != null) applyRoles(user, request.roles());
        if (request.ims() != null) applyIms(user, request.ims());
        if (request.photos() != null) applyPhotos(user, request.photos());
        if (request.x509Certificates() != null) applyX509Certs(user, request.x509Certificates());
    }

    private void applyScalarUserFields(ScimUser user, UserUpsertRequest request, boolean isCreate) {
        applyIfChanged(isCreate, request.displayName(), user::setDisplayName);
        applyIfChanged(isCreate, request.externalId(), user::setExternalId);
        if (request.active() != null) user.setActive(request.active());
        applyIfChanged(isCreate, request.nameFormatted(), user::setNameFormatted);
        applyIfChanged(isCreate, request.nameFamilyName(), user::setNameFamilyName);
        applyIfChanged(isCreate, request.nameGivenName(), user::setNameGivenName);
        applyIfChanged(isCreate, request.nameMiddleName(), user::setNameMiddleName);
        applyIfChanged(isCreate, request.nameHonorificPrefix(), user::setNameHonorificPrefix);
        applyIfChanged(isCreate, request.nameHonorificSuffix(), user::setNameHonorificSuffix);
        applyIfChanged(isCreate, request.nickName(), user::setNickName);
        applyIfChanged(isCreate, request.profileUrl(), user::setProfileUrl);
        applyIfChanged(isCreate, request.title(), user::setTitle);
        applyIfChanged(isCreate, request.userType(), user::setUserType);
        applyIfChanged(isCreate, request.preferredLanguage(), user::setPreferredLanguage);
        applyIfChanged(isCreate, request.locale(), user::setLocale);
        applyIfChanged(isCreate, request.timezone(), user::setTimezone);
        applyPassword(user, request.password(), isCreate);
        applyIfChanged(isCreate, request.enterpriseEmployeeNumber(), user::setEnterpriseEmployeeNumber);
        applyIfChanged(isCreate, request.enterpriseCostCenter(), user::setEnterpriseCostCenter);
        applyIfChanged(isCreate, request.enterpriseOrganization(), user::setEnterpriseOrganization);
        applyIfChanged(isCreate, request.enterpriseDivision(), user::setEnterpriseDivision);
        applyIfChanged(isCreate, request.enterpriseDepartment(), user::setEnterpriseDepartment);
        applyIfChanged(isCreate, request.enterpriseManagerValue(), user::setEnterpriseManagerValue);
        applyIfChanged(isCreate, request.enterpriseManagerRef(), user::setEnterpriseManagerRef);
        applyIfChanged(isCreate, request.enterpriseManagerDisplay(), user::setEnterpriseManagerDisplay);
    }

    private void applyPassword(ScimUser user, String rawPassword, boolean isCreate) {
        if (rawPassword == null || rawPassword.isBlank()) {
            if (isCreate) {
                user.setPassword(null);
            }
            return;
        }
        int utf8Bytes = rawPassword.getBytes(StandardCharsets.UTF_8).length;
        if (utf8Bytes > MAX_BCRYPT_PASSWORD_BYTES) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password must not exceed " + MAX_BCRYPT_PASSWORD_BYTES + " UTF-8 bytes");
        }
        user.setPassword(passwordEncoder.encode(rawPassword));
    }

    private void applyIfChanged(boolean isCreate, String value, Consumer<String> setter) {
        if (isCreate || value != null) {
            setter.accept(normalizeOptional(value));
        }
    }

    private void applyEmails(ScimUser user, List<UserUpsertRequest.MultiValue> emails) {
        user.getEmails().clear();
        for (UserUpsertRequest.MultiValue mv : emails) {
            ScimUserEmail email = new ScimUserEmail();
            email.setValue(normalizeOptional(mv.value()));
            email.setType(normalizeOptional(mv.type()));
            email.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) email.setPrimaryFlag(mv.primary());
            user.getEmails().add(email);
        }
    }

    private void applyPhoneNumbers(ScimUser user, List<UserUpsertRequest.MultiValue> phones) {
        user.getPhoneNumbers().clear();
        for (UserUpsertRequest.MultiValue mv : phones) {
            ScimUserPhoneNumber phone = new ScimUserPhoneNumber();
            phone.setValue(normalizeOptional(mv.value()));
            phone.setType(normalizeOptional(mv.type()));
            phone.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) phone.setPrimaryFlag(mv.primary());
            user.getPhoneNumbers().add(phone);
        }
    }

    private void applyAddresses(ScimUser user, List<UserUpsertRequest.Address> addresses) {
        user.getAddresses().clear();
        for (UserUpsertRequest.Address addr : addresses) {
            ScimUserAddress address = new ScimUserAddress();
            address.setFormatted(normalizeOptional(addr.formatted()));
            address.setStreetAddress(normalizeOptional(addr.streetAddress()));
            address.setLocality(normalizeOptional(addr.locality()));
            address.setRegion(normalizeOptional(addr.region()));
            address.setPostalCode(normalizeOptional(addr.postalCode()));
            address.setCountry(normalizeOptional(addr.country()));
            address.setType(normalizeOptional(addr.type()));
            if (addr.primary() != null) address.setPrimaryFlag(addr.primary());
            user.getAddresses().add(address);
        }
    }

    private void applyEntitlements(ScimUser user, List<UserUpsertRequest.MultiValue> entitlements) {
        user.getEntitlements().clear();
        for (UserUpsertRequest.MultiValue mv : entitlements) {
            ScimUserEntitlement entitlement = new ScimUserEntitlement();
            entitlement.setValue(normalizeOptional(mv.value()));
            entitlement.setType(normalizeOptional(mv.type()));
            entitlement.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) entitlement.setPrimaryFlag(mv.primary());
            user.getEntitlements().add(entitlement);
        }
    }

    private void applyRoles(ScimUser user, List<UserUpsertRequest.MultiValue> roles) {
        user.getRoles().clear();
        for (UserUpsertRequest.MultiValue mv : roles) {
            ScimUserRole role = new ScimUserRole();
            role.setValue(normalizeOptional(mv.value()));
            role.setType(normalizeOptional(mv.type()));
            role.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) role.setPrimaryFlag(mv.primary());
            user.getRoles().add(role);
        }
    }

    private void applyIms(ScimUser user, List<UserUpsertRequest.MultiValue> ims) {
        user.getIms().clear();
        for (UserUpsertRequest.MultiValue mv : ims) {
            ScimUserIm im = new ScimUserIm();
            im.setValue(normalizeOptional(mv.value()));
            im.setType(normalizeOptional(mv.type()));
            im.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) im.setPrimaryFlag(mv.primary());
            user.getIms().add(im);
        }
    }

    private void applyPhotos(ScimUser user, List<UserUpsertRequest.MultiValue> photos) {
        user.getPhotos().clear();
        for (UserUpsertRequest.MultiValue mv : photos) {
            ScimUserPhoto photo = new ScimUserPhoto();
            photo.setValue(normalizeOptional(mv.value()));
            photo.setType(normalizeOptional(mv.type()));
            photo.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) photo.setPrimaryFlag(mv.primary());
            user.getPhotos().add(photo);
        }
    }

    private void applyX509Certs(ScimUser user, List<UserUpsertRequest.MultiValue> certs) {
        user.getX509Certificates().clear();
        for (UserUpsertRequest.MultiValue mv : certs) {
            ScimUserX509Certificate cert = new ScimUserX509Certificate();
            cert.setValue(normalizeOptional(mv.value()));
            cert.setType(normalizeOptional(mv.type()));
            cert.setDisplay(normalizeOptional(mv.display()));
            if (mv.primary() != null) cert.setPrimaryFlag(mv.primary());
            user.getX509Certificates().add(cert);
        }
    }

    private void applyGroupFields(ScimGroup group, GroupUpsertRequest request, boolean isCreate) {
        if (isCreate || request.externalId() != null) {
            group.setExternalId(normalizeOptional(request.externalId()));
        }
        if (request.members() != null) {
            UUID wsId = group.getWorkspace() != null ? group.getWorkspace().getId() : null;
            if (wsId == null) {
                throw new IllegalStateException("Group requires a workspace id before resolving members");
            }
            group.getMembers().clear();
            Set<UUID> seenMembers = new HashSet<>();
            for (GroupUpsertRequest.Member member : request.members()) {
                ScimGroupMembership membership = buildMembership(group, wsId, member, seenMembers);
                if (membership != null) {
                    group.getMembers().add(membership);
                }
            }
        }
    }

    private ScimGroupMembership buildMembership(ScimGroup group,
                                                UUID workspaceId,
                                                GroupUpsertRequest.Member member,
                                                Set<UUID> seenMembers) {
        if (member == null || member.value() == null || member.value().isBlank()) {
            return null;
        }
        UUID memberUuid;
        try {
            memberUuid = UUID.fromString(member.value().trim());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid member UUID: " + member.value(), ex);
        }
        if (!seenMembers.add(memberUuid)) {
            return null;
        }

        String rawType = normalizeOptional(member.type());
        String canonicalType;
        if (rawType == null || MEMBER_TYPE_USER.equalsIgnoreCase(rawType)) {
            canonicalType = MEMBER_TYPE_USER;
        } else if (MEMBER_TYPE_GROUP.equalsIgnoreCase(rawType)) {
            canonicalType = MEMBER_TYPE_GROUP;
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported member type: " + rawType);
        }

        if (MEMBER_TYPE_GROUP.equals(canonicalType)) {
            if (group.getId() != null && group.getId().equals(memberUuid)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Group cannot include itself as a member");
            }
            if (!groupRepository.existsByIdAndWorkspaceId(memberUuid, workspaceId)) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Member group does not exist in workspace: " + memberUuid);
            }
        } else if (!userRepository.existsByIdAndWorkspaceId(memberUuid, workspaceId)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Member user does not exist in workspace: " + memberUuid);
        }

        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setWorkspaceId(workspaceId);
        membership.setMemberValue(memberUuid);
        membership.setMemberType(canonicalType);
        membership.setDisplay(normalizeOptional(member.display()));
        return membership;
    }

    private String normalizeRequired(String field, String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
        }
        return value.trim();
    }

    private String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    

    private void initializeLazyGroupCollections(ScimGroup group) {
        if (group != null) {
            Hibernate.initialize(group.getMembers());
        }
    }
}
