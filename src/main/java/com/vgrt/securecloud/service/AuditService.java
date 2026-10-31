package com.vgrt.securecloud.service;

import com.vgrt.securecloud.entity.AuditEvent;
import com.vgrt.securecloud.repository.AuditEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {
    private final AuditEventRepository events;
    public AuditService(AuditEventRepository events) { this.events = events; }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String actor, String type, String resourceId, String outcome, String details) {
        events.save(new AuditEvent(actor, type, resourceId, outcome, details));
    }
}
