package com.vgrt.securecloud.repository;

import com.vgrt.securecloud.entity.AuditEvent;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {
    List<AuditEvent> findTop100ByOrderByOccurredAtDesc();
    List<AuditEvent> findTop50ByActorUsernameOrderByOccurredAtDesc(String actorUsername);
    long countByActorUsername(String actorUsername);
    long countByActorUsernameAndOutcome(String actorUsername, String outcome);
}
