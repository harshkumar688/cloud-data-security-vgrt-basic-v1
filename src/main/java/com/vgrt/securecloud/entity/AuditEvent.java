package com.vgrt.securecloud.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "audit_events")
public class AuditEvent {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(length = 80) private String actorUsername;
    @Column(nullable = false, length = 40) private String eventType;
    @Column(length = 80) private String resourceId;
    @Column(nullable = false, length = 20) private String outcome;
    @Column(nullable = false, length = 300) private String details;
    @Column(nullable = false) private Instant occurredAt = Instant.now();

    protected AuditEvent() {}
    public AuditEvent(String actorUsername, String eventType, String resourceId, String outcome, String details) {
        this.actorUsername = actorUsername; this.eventType = eventType; this.resourceId = resourceId;
        this.outcome = outcome; this.details = details;
    }
    public Long getId() { return id; }
    public String getActorUsername() { return actorUsername; }
    public String getEventType() { return eventType; }
    public String getResourceId() { return resourceId; }
    public String getOutcome() { return outcome; }
    public String getDetails() { return details; }
    public Instant getOccurredAt() { return occurredAt; }
}
