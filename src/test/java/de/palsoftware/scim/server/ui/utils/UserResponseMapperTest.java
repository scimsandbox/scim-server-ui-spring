package de.palsoftware.scim.server.ui.utils;

import de.palsoftware.scim.server.ui.model.ScimUser;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class UserResponseMapperTest {

    @Test
    void userToMapTreatsMissingMultiValuedAttributesAsEmptyLists() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("user@example.test");

        Map<String, Object> result = assertDoesNotThrow(() -> UserResponseMapper.userToMap(user));

        assertThat(result)
            .containsEntry("emails", List.of())
            .containsEntry("phoneNumbers", List.of())
            .containsEntry("addresses", List.of())
            .containsEntry("entitlements", List.of())
            .containsEntry("roles", List.of())
            .containsEntry("ims", List.of())
            .containsEntry("photos", List.of())
            .containsEntry("x509Certificates", List.of());
    }

    @Test
    void userToMapNeverExposesPasswordOrPasswordHash() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("alice@example.test");
        user.setPassword("$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234");

        Map<String, Object> fullMap = UserResponseMapper.userToMap(user);
        Map<String, Object> lookupMap = UserResponseMapper.userLookupToMap(user);

        assertThat(fullMap).doesNotContainKey("password");
        assertThat(fullMap.toString()).doesNotContain("$2a$10$");
        assertThat(lookupMap).doesNotContainKey("password");
    }
}
