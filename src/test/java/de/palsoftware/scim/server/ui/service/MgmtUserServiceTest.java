package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.MgmtUser;
import de.palsoftware.scim.server.ui.repository.MgmtUserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MgmtUserServiceTest {

    @Mock
    private MgmtUserRepository mgmtUserRepository;

    @InjectMocks
    private MgmtUserService service;

    // ─── provisionUser ──────────────────────────────────────────────────

    @Test
    void provisionUser_newUser_createsAndSavesNormalizedEmail() {
        when(mgmtUserRepository.findById("user@test.com")).thenReturn(Optional.empty());
        when(mgmtUserRepository.save(any(MgmtUser.class))).thenAnswer(i -> i.getArgument(0));

        service.provisionUser(" User@Test.com ");

        verify(mgmtUserRepository).save(argThat(user -> "user@test.com".equals(user.getEmail())
                && user.getLastLoginAt() != null));
    }

    @Test
    void provisionUser_existingUser_updatesLoginTime() {
        MgmtUser existing = new MgmtUser("user@test.com", OffsetDateTime.now(ZoneOffset.UTC).minusDays(1));
        when(mgmtUserRepository.findById("user@test.com")).thenReturn(Optional.of(existing));
        when(mgmtUserRepository.save(any(MgmtUser.class))).thenAnswer(i -> i.getArgument(0));

        service.provisionUser("USER@Test.com");

        assertThat(existing.getEmail()).isEqualTo("user@test.com");
        verify(mgmtUserRepository).save(existing);
    }

    @Test
    void provisionUser_missingEmail_throws() {
        assertThatThrownBy(() -> service.provisionUser("not-an-email"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("email is required");
    }

    // ─── resolveDisplayName ─────────────────────────────────────────────

    @Test
    void resolveDisplayName_found() {
        MgmtUser user = new MgmtUser("user@test.com", OffsetDateTime.now(ZoneOffset.UTC));
        when(mgmtUserRepository.findById("user@test.com")).thenReturn(Optional.of(user));

        Optional<String> result = service.resolveDisplayName("User@Test.com");

        assertThat(result).contains("user@test.com");
    }

    @Test
    void resolveDisplayName_notFound() {
        when(mgmtUserRepository.findById("missing@test.com")).thenReturn(Optional.empty());

        Optional<String> result = service.resolveDisplayName("missing@test.com");

        assertThat(result).isEmpty();
    }

    @Test
    void resolveDisplayName_invalidEmail_returnsEmpty() {
        Optional<String> result = service.resolveDisplayName("not-an-email");

        assertThat(result).isEmpty();
    }
}
