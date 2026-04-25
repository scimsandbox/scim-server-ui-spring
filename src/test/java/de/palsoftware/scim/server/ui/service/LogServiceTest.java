package de.palsoftware.scim.server.ui.service;

import de.palsoftware.scim.server.ui.model.ScimRequestLog;
import de.palsoftware.scim.server.ui.repository.ScimRequestLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LogServiceTest {

    @Mock
    private ScimRequestLogRepository logRepository;

    @InjectMocks
    private LogService service;

    private final UUID workspaceId = UUID.randomUUID();

    @Test
    void listLogs_delegates() {
        PageRequest pageable = PageRequest.of(0, 20);
        when(logRepository.findByWorkspace_IdOrderByCreatedAtDesc(workspaceId, pageable))
                .thenReturn(new PageImpl<>(Collections.emptyList()));

        Page<ScimRequestLog> result = service.listLogs(workspaceId, pageable);

        assertThat(result.getTotalElements()).isZero();
    }

    @Test
    void clearLogs_delegates() {
        service.clearLogs(workspaceId);

        verify(logRepository).deleteByWorkspaceId(workspaceId);
    }
}
