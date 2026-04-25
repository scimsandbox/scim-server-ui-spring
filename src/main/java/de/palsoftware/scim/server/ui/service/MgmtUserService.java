package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.MgmtUser;
import de.palsoftware.scim.server.ui.repository.MgmtUserRepository;
import de.palsoftware.scim.server.ui.security.AuthenticatedUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class MgmtUserService {

    private final MgmtUserRepository mgmtUserRepository;

    public MgmtUserService(MgmtUserRepository mgmtUserRepository) {
        this.mgmtUserRepository = mgmtUserRepository;
    }

    @Transactional
    public void provisionUser(String email) {
        String normalizedEmail = requireEmail(email);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        MgmtUser user = mgmtUserRepository.findById(normalizedEmail)
                .orElseGet(() -> new MgmtUser(normalizedEmail, now));
        user.setEmail(normalizedEmail);
        user.setLastLoginAt(now);
        mgmtUserRepository.save(user);
    }

    public Optional<String> resolveDisplayName(String email) {
        String normalizedEmail = AuthenticatedUser.normalizeEmail(email);
        if (normalizedEmail == null) {
            return Optional.empty();
        }
        return mgmtUserRepository.findById(normalizedEmail)
                .map(MgmtUser::getEmail)
                .filter(e -> e != null && !e.isBlank());
    }

    private String requireEmail(String email) {
        String normalizedEmail = AuthenticatedUser.normalizeEmail(email);
        if (normalizedEmail == null) {
            throw new IllegalArgumentException("Management user email is required");
        }
        return normalizedEmail;
    }
}

