package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.ScimRequestLog;
import de.palsoftware.scim.server.ui.repository.ScimRequestLogRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@Transactional(readOnly = true)
public class LogService {

    private final ScimRequestLogRepository logRepository;

    public LogService(ScimRequestLogRepository logRepository) {
        this.logRepository = logRepository;
    }

    public Page<ScimRequestLog> listLogs(UUID workspaceId, Pageable pageable) {
        return logRepository.findByWorkspace_IdOrderByCreatedAtDesc(workspaceId, pageable);
    }

    @Transactional
    public void clearLogs(UUID workspaceId) {
        logRepository.deleteByWorkspaceId(workspaceId);
    }
}
