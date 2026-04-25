package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.dto.GroupUpsertRequest;
import de.palsoftware.scim.server.ui.dto.UserUpsertRequest;
import de.palsoftware.scim.server.ui.model.ScimGroup;
import de.palsoftware.scim.server.ui.model.ScimGroupMembership;
import de.palsoftware.scim.server.ui.model.ScimUser;
import de.palsoftware.scim.server.ui.repository.ScimGroupRepository;
import de.palsoftware.scim.server.ui.repository.ScimUserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@Transactional(readOnly = true)
public class DataGeneratorService {

    private static final int DEFAULT_COUNT = 12;
    private static final int MAX_COUNT = 200;

    private static final List<String> FIRST_NAMES = List.of(
            "Ava", "Noah", "Mila", "Liam", "Zoe", "Ethan", "Isla", "Leo",
            "Nora", "Mason", "Ruby", "Kai", "Ivy", "Owen", "Clara", "Ezra");
    private static final List<String> LAST_NAMES = List.of(
            "Nguyen", "Patel", "Kim", "Smith", "Garcia", "Brown", "Lopez", "Davis",
            "Wilson", "Martin", "Clark", "Young", "Turner", "Wright", "Scott", "Adams");
    private static final List<String> DEPARTMENTS = List.of(
            "Engineering", "Platform", "Security", "Operations", "Sales", "Support", "Finance", "Marketing");
    private static final List<String> DIVISIONS = List.of(
            "North America", "EMEA", "APAC", "Core Products", "Identity", "Data Services");
    private static final List<String> TITLES = List.of(
            "Software Engineer", "Product Manager", "Support Engineer", "Security Analyst",
            "Solutions Architect", "QA Engineer", "DevOps Engineer", "Technical Writer");
    private static final List<String> GROUP_PREFIXES = List.of(
            "Team", "Squad", "Circle", "Guild", "Program", "Chapter");
    private static final List<String> CITIES = List.of("New York", "London", "Berlin", "Toronto", "Sydney",
            "Singapore");
    private static final List<String> REGIONS = List.of("NY", "LND", "BE", "ON", "NSW", "SG");
    private static final List<String> COUNTRIES = List.of("US", "GB", "DE", "CA", "AU", "SG");
    private static final List<String> TIMEZONES = List.of(
            "America/New_York", "Europe/London", "Europe/Berlin", "America/Toronto", "Australia/Sydney",
            "Asia/Singapore");

    private final WorkspaceService workspaceService;
    private final ScimAdminService scimAdminService;
    private final ScimUserRepository scimUserRepository;
    private final ScimGroupRepository scimGroupRepository;

    public DataGeneratorService(WorkspaceService workspaceService,
            ScimAdminService scimAdminService,
            ScimUserRepository scimUserRepository,
            ScimGroupRepository scimGroupRepository) {
        this.workspaceService = workspaceService;
        this.scimAdminService = scimAdminService;
        this.scimUserRepository = scimUserRepository;
        this.scimGroupRepository = scimGroupRepository;
    }

    @Transactional
    public GenerationSummary generateUsers(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        return doGenerateUsers(workspaceId, requestedCount, actorUsername, admin);
    }

    private GenerationSummary doGenerateUsers(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        workspaceService.requireWorkspaceAccess(workspaceId, actorUsername, admin);
        int appliedCount = sanitizeCount(requestedCount);
        for (int index = 0; index < appliedCount; index++) {
            SampleProfile profile = randomProfile();
            String userName = nextUniqueUserName(workspaceId, profile, index);
            scimAdminService.createUser(workspaceId, buildUserRequest(userName, profile, index), actorUsername, admin);
        }
        return new GenerationSummary(requestedCountOrDefault(requestedCount), appliedCount, appliedCount, 0, 0);
    }

    @Transactional
    public GenerationSummary generateGroups(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        return doGenerateGroups(workspaceId, requestedCount, actorUsername, admin);
    }

    private GenerationSummary doGenerateGroups(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        workspaceService.requireWorkspaceAccess(workspaceId, actorUsername, admin);
        int appliedCount = sanitizeCount(requestedCount);
        for (int index = 0; index < appliedCount; index++) {
            String displayName = nextUniqueGroupName(workspaceId, index);
            String externalId = "GEN-GRP-" + randomCode(8).toUpperCase(Locale.ROOT);
            scimAdminService.createGroup(
                    workspaceId,
                    new GroupUpsertRequest(displayName, externalId, null),
                    actorUsername,
                    admin);
        }
        return new GenerationSummary(requestedCountOrDefault(requestedCount), appliedCount, 0, appliedCount, 0);
    }

    @Transactional
    public GenerationSummary generateRelations(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        return doGenerateRelations(workspaceId, requestedCount, actorUsername, admin);
    }

    private GenerationSummary doGenerateRelations(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        workspaceService.requireWorkspaceAccess(workspaceId, actorUsername, admin);
        int appliedCount = sanitizeCount(requestedCount);
        List<ScimUser> users = new ArrayList<>(scimUserRepository.findByWorkspaceId(workspaceId));
        List<ScimGroup> groups = new ArrayList<>(scimGroupRepository.findByWorkspaceId(workspaceId));
        if (users.isEmpty() || groups.isEmpty()) {
            return new GenerationSummary(requestedCountOrDefault(requestedCount), appliedCount, 0, 0, 0);
        }

        int created = 0;
        int maxAttempts = Math.max(appliedCount * 10, 50);
        int attempts = 0;
        while (created < appliedCount && attempts < maxAttempts) {
            attempts++;
            ScimUser user = users.get(ThreadLocalRandom.current().nextInt(users.size()));
            ScimGroup group = groups.get(ThreadLocalRandom.current().nextInt(groups.size()));
            if (hasMembership(group, user.getId())) {
                continue;
            }
            ScimGroupMembership membership = new ScimGroupMembership();
            membership.setGroup(group);
            membership.setMemberValue(user.getId());
            membership.setMemberType("User");
            membership.setDisplay(user.getDisplayName() != null ? user.getDisplayName() : user.getUserName());
            group.getMembers().add(membership);
            scimGroupRepository.save(group);
            created++;
        }

        return new GenerationSummary(requestedCountOrDefault(requestedCount), appliedCount, 0, 0, created);
    }

    @Transactional
    public GenerationSummary generateAll(UUID workspaceId, Integer requestedCount, String actorUsername,
            boolean admin) {
        int appliedCount = sanitizeCount(requestedCount);
        GenerationSummary users = doGenerateUsers(workspaceId, appliedCount, actorUsername, admin);
        GenerationSummary groups = doGenerateGroups(workspaceId, appliedCount, actorUsername, admin);
        GenerationSummary relations = doGenerateRelations(workspaceId, appliedCount, actorUsername, admin);
        return new GenerationSummary(
                requestedCountOrDefault(requestedCount),
                appliedCount,
                users.usersCreated(),
                groups.groupsCreated(),
                relations.relationsCreated());
    }

    private UserUpsertRequest buildUserRequest(String userName, SampleProfile profile, int index) {
        String displayName = profile.firstName() + " " + profile.lastName();
        String profileSlug = userName.replace('.', '-');
        String employeeNumber = String.format(Locale.ROOT, "EMP-%05d", ThreadLocalRandom.current().nextInt(1, 99999));
        List<UserUpsertRequest.MultiValue> emails = List.of(
                new UserUpsertRequest.MultiValue(userName + "@example.test", "work", displayName, true));
        List<UserUpsertRequest.MultiValue> phoneNumbers = List.of(
                new UserUpsertRequest.MultiValue(randomPhoneNumber(index), "work", null, true));
        List<UserUpsertRequest.Address> addresses = List.of(
                new UserUpsertRequest.Address(
                        (100 + index) + " Market Street",
                        (100 + index) + " Market Street",
                        profile.city(),
                        profile.region(),
                        profile.postalCode(),
                        profile.country(),
                        "work",
                        true));
        List<UserUpsertRequest.MultiValue> entitlements = List.of(
                new UserUpsertRequest.MultiValue("playground-access", "app", "Playground Access", true));
        List<UserUpsertRequest.MultiValue> roles = List.of(
                new UserUpsertRequest.MultiValue(profile.department().toLowerCase(Locale.ROOT), "department",
                        profile.department(), true));
        return new UserUpsertRequest(
                userName,
                displayName,
                true,
                "GEN-USER-" + randomCode(8).toUpperCase(Locale.ROOT),
                displayName,
                profile.lastName(),
                profile.firstName(),
                null,
                null,
                null,
                profile.firstName(),
                "https://profiles.example.test/users/" + profileSlug,
                profile.title(),
                "Employee",
                "en-US",
                "en_US",
                profile.timezone(),
                null,
                employeeNumber,
                profile.costCenter(),
                "SCIM Playground",
                profile.division(),
                profile.department(),
                null,
                null,
                null,
                emails,
                phoneNumbers,
                addresses,
                entitlements,
                roles,
                null,
                null,
                null);
    }

    private SampleProfile randomProfile() {
        return new SampleProfile(
                pick(FIRST_NAMES),
                pick(LAST_NAMES),
                pick(DEPARTMENTS),
                pick(DIVISIONS),
                pick(TITLES),
                pick(CITIES),
                pick(REGIONS),
                pick(COUNTRIES),
                String.format(Locale.ROOT, "%05d", ThreadLocalRandom.current().nextInt(10000, 99999)),
                pick(TIMEZONES),
                "CC-" + String.format(Locale.ROOT, "%03d", ThreadLocalRandom.current().nextInt(1, 500)));
    }

    private String nextUniqueUserName(UUID workspaceId, SampleProfile profile, int index) {
        String base = (profile.firstName() + "." + profile.lastName()).toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9.]+", "");
        String candidate = base + "." + randomCode(4) + index;
        while (scimUserRepository.existsByUserNameIgnoreCaseAndWorkspaceId(candidate, workspaceId)) {
            candidate = base + "." + randomCode(6);
        }
        return candidate;
    }

    private String nextUniqueGroupName(UUID workspaceId, int index) {
        String candidate = pick(GROUP_PREFIXES) + " " + pick(DEPARTMENTS) + " "
                + randomCode(4).toUpperCase(Locale.ROOT);
        while (scimGroupRepository.existsByDisplayNameAndWorkspaceId(candidate, workspaceId)) {
            candidate = pick(GROUP_PREFIXES) + " " + pick(DEPARTMENTS) + " " + index + " "
                    + randomCode(4).toUpperCase(Locale.ROOT);
        }
        return candidate;
    }

    private boolean hasMembership(ScimGroup group, UUID memberId) {
        return group.getMembers().stream().anyMatch(member -> memberId.equals(member.getMemberValue()));
    }

    private int sanitizeCount(Integer requestedCount) {
        if (requestedCount == null) {
            return DEFAULT_COUNT;
        }
        return Math.max(1, Math.min(requestedCount, MAX_COUNT));
    }

    private int requestedCountOrDefault(Integer requestedCount) {
        return requestedCount != null ? requestedCount : DEFAULT_COUNT;
    }

    private String randomPhoneNumber(int index) {
        return String.format(Locale.ROOT, "+1-555-%04d",
                1000 + ((index + ThreadLocalRandom.current().nextInt(9000)) % 9000));
    }

    private String randomCode(int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder value = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            value.append(alphabet.charAt(ThreadLocalRandom.current().nextInt(alphabet.length())));
        }
        return value.toString();
    }

    private String pick(List<String> values) {
        return values.get(ThreadLocalRandom.current().nextInt(values.size()));
    }

    public record GenerationSummary(
            int requestedCount,
            int appliedCount,
            int usersCreated,
            int groupsCreated,
            int relationsCreated) {
    }

    private record SampleProfile(
            String firstName,
            String lastName,
            String department,
            String division,
            String title,
            String city,
            String region,
            String country,
            String postalCode,
            String timezone,
            String costCenter) {
    }
}