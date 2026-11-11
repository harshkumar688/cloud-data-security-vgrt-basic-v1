package com.vgrt.securecloud.repository;

import com.vgrt.securecloud.entity.AuditEvent;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {
    Optional<AuditEvent> findTop1ByOrderByIdDesc();
    List<AuditEvent> findAllByOrderByIdAsc();
    List<AuditEvent> findAllByOrderByIdDesc();
    List<AuditEvent> findAllByActorUsernameOrderByIdDesc(String actorUsername);
    List<AuditEvent> findAllByActorUsernameOrderByIdAsc(String actorUsername);

    List<AuditEvent> findTop100ByOrderByOccurredAtDesc();
    List<AuditEvent> findTop50ByOrderByOccurredAtDesc();
    List<AuditEvent> findTop30ByOrderByOccurredAtDesc();
    List<AuditEvent> findTop50ByActorUsernameOrderByOccurredAtDesc(String actorUsername);

    long countByActorUsername(String actorUsername);
    long countByOutcome(String outcome);
    long countByActorUsernameAndOutcome(String actorUsername, String outcome);
    long countByEventTypeAndOutcome(String eventType, String outcome);
    long countByActorUsernameAndEventTypeAndOutcome(String actorUsername, String eventType, String outcome);

    List<AuditEvent> findTop50ByOutcomeOrderByOccurredAtDesc(String outcome);
    List<AuditEvent> findTop50ByActorUsernameAndOutcomeOrderByOccurredAtDesc(String actorUsername, String outcome);
    List<AuditEvent> findTop20ByEventTypeOrderByOccurredAtDesc(String eventType);
}
