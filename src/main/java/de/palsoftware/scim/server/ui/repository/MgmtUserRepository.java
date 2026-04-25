package de.palsoftware.scim.server.ui.repository;

import de.palsoftware.scim.server.ui.model.MgmtUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MgmtUserRepository extends JpaRepository<MgmtUser, String> {
}
