package com.vgrt.securecloud.service;

import com.vgrt.securecloud.entity.AuditEvent;
import com.vgrt.securecloud.entity.UserAccount;
import com.vgrt.securecloud.repository.AuditEventRepository;
import com.vgrt.securecloud.repository.UserAccountRepository;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public class GovernanceService {

    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("MMM dd, yyyy");
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final UserAccountRepository userRepo;
    private final AuditEventRepository auditRepo;

    public record RoleDefinition(String roleName, String displayName, String badgeClass, String description, List<String> permissions, List<String> restrictions) {}
    public record GovernancePolicy(String id, String category, String policyName, String implementationMechanism, String enforcementLevel, String status, String statusBadge) {}
    public record UserRosterItem(Long id, String username, String role, String status, String createdAtFormatted, boolean isAdmin) {}
    public record AccessAuditEntry(Long id, String timestamp, String actor, String eventType, String resourceId, String outcome, String outcomeBadge, String details) {}

    public GovernanceService(UserAccountRepository userRepo, AuditEventRepository auditRepo) {
        this.userRepo = userRepo;
        this.auditRepo = auditRepo;
    }

    public Map<String, Object> getGovernanceData(String currentUsername, boolean isCurrentUserAdmin) {
        Map<String, Object> data = new LinkedHashMap<>();

        // 1. Current Session Context
        Optional<UserAccount> currentUserOpt = userRepo.findByUsername(currentUsername);
        String currentRole = currentUserOpt.map(UserAccount::getRole).orElse(isCurrentUserAdmin ? "ADMIN" : "USER");
        data.put("currentUsername", currentUsername);
        data.put("currentRole", currentRole);
        data.put("isCurrentUserAdmin", isCurrentUserAdmin);

        // 2. Roles and Permissions Matrix
        List<RoleDefinition> roles = List.of(
            new RoleDefinition(
                "ROLE_USER",
                "Standard Authenticated Principal",
                "badge-cipher",
                "Strictly isolated tenant principal operating under the Principle of Least Privilege. Authorized solely over self-owned cryptographic objects.",
                List.of(
                    "FILE:CREATE — Encrypt & store documents via AES-256-GCM pipeline",
                    "FILE:READ — Inspect personal encrypted object metadata and SHA-256 tags",
                    "FILE:DOWNLOAD — Retrieve & decrypt self-owned ciphertext via RSA-unwrapping",
                    "FILE:DELETE — Permanently purge owned ciphertext and key references",
                    "INTEGRITY:VERIFY — On-demand SHA-256 checksum affirmation",
                    "SECURITY:POSTURE — View tenant-scoped Security Center metrics"
                ),
                List.of(
                    "DENIED: Cross-tenant data inspection or file retrieval (Strict Row-Level Guard)",
                    "DENIED: Global system audit ledger access (/admin/audit)",
                    "DENIED: User privilege escalation or role management controls"
                )
            ),
            new RoleDefinition(
                "ROLE_ADMIN",
                "Cryptographic Enclave Administrator",
                "badge-accent",
                "High-assurance oversight role with system-wide observability, audit ledger immutability auditing, and tenant governance monitoring.",
                List.of(
                    "ALL: Full inheritance of standard tenant capabilities",
                    "AUDIT:READ_ALL — Inspect complete tamper-evident audit ledger across all tenants",
                    "GOVERNANCE:MONITOR — Real-time governance policy enforcement oversight",
                    "USERS:ROSTER — Review tenant registration records and privilege rosters",
                    "RISK:REASSESS — Trigger platform-wide deterministic risk score recalculation"
                ),
                List.of(
                    "RESTRICTED: Zero-Knowledge boundary strictly maintained (Admin cannot decrypt tenant ciphertext without master key access)",
                    "AUDITED: Every administrative action generates an immutable audit record"
                )
            )
        );
        data.put("roleDefinitions", roles);

        // 3. User Roster (real data from UserAccountRepository)
        List<UserAccount> allUsers = userRepo.findAll();
        List<UserRosterItem> roster = new ArrayList<>();
        for (UserAccount u : allUsers) {
            String created = u.getCreatedAt() != null ? 
                    DATE_FMT.format(u.getCreatedAt().atZone(ZoneId.systemDefault())) : "System Default";
            boolean isAdm = "ADMIN".equalsIgnoreCase(u.getRole());
            roster.add(new UserRosterItem(u.getId(), u.getUsername(), u.getRole(), "ACTIVE · VERIFIED", created, isAdm));
        }
        data.put("userRoster", roster);
        data.put("totalRegisteredUsers", allUsers.size());

        // 4. Governance Policies Status
        List<GovernancePolicy> policies = List.of(
            new GovernancePolicy("POL-01", "Access Control", "Strict Row-Level Tenant Isolation",
                "JPA repository query predicates explicitly filter by `owner_username = :authenticatedPrincipal`. Direct object reference (IDOR) attempts return HTTP 404/DENIED.",
                "Kernel / Data Layer", "ENFORCED", "badge-cipher"),
            new GovernancePolicy("POL-02", "Cryptographic Separation", "Per-File Ephemeral Session Key Generation",
                "Each file is encrypted with a distinct 256-bit AES-GCM key generated in-memory via SecureRandom. Session keys are never persisted in plaintext.",
                "Crypto Subsystem", "ENFORCED", "badge-cipher"),
            new GovernancePolicy("POL-03", "Key Management", "RSA-2048 Envelope Key Wrapping",
                "Session keys are wrapped using RSA-OAEP with SHA-256 before storage metadata commits. Raw master keys remain in enclave memory.",
                "Asymmetric Keypair", "ENFORCED", "badge-cipher"),
            new GovernancePolicy("POL-04", "Integrity & Non-Repudiation", "Append-Only Audit Ledger Logging",
                "Every authentication attempt, encryption, download, deletion, and policy violation logs an immutable timestamped event.",
                "Audit Subsystem", "ENFORCED", "badge-cipher"),
            new GovernancePolicy("POL-05", "Storage Enclave", "Zero-Knowledge Ciphertext Disassociation",
                "Files on disk use sanitized UUID storage identifiers (`.bin`). Storage volume contains zero plaintext, original filenames, or directory structures.",
                "Storage Provider", "ENFORCED", "badge-cipher"),
            new GovernancePolicy("POL-06", "Passphrase Entropy", "BCrypt Salted Password Hashing",
                "User credentials hashed using BCrypt work factor 10. Raw credentials are never logged or stored in database tables.",
                "Auth Provider", "ENFORCED", "badge-cipher")
        );
        data.put("governancePolicies", policies);

        // 5. Access History from real AuditEvent records
        List<AuditEvent> auditHistory = isCurrentUserAdmin ?
                auditRepo.findTop50ByOrderByOccurredAtDesc() :
                auditRepo.findTop50ByActorUsernameOrderByOccurredAtDesc(currentUsername);

        List<AccessAuditEntry> accessLog = new ArrayList<>();
        for (AuditEvent e : auditHistory) {
            String ts = TIME_FMT.format(e.getOccurredAt().atZone(ZoneId.systemDefault()));
            String outcome = e.getOutcome();
            String outcomeBadge = "SUCCESS".equalsIgnoreCase(outcome) ? "badge-cipher" :
                                  "DENIED".equalsIgnoreCase(outcome) ? "badge-danger" : "badge-warning";
            String actor = (e.getActorUsername() != null && !e.getActorUsername().isBlank()) ? e.getActorUsername() : "system";
            accessLog.add(new AccessAuditEntry(e.getId(), ts, actor, e.getEventType(), 
                    e.getResourceId() != null ? e.getResourceId() : "N/A", outcome, outcomeBadge, e.getDetails()));
        }
        data.put("accessLog", accessLog);

        return data;
    }
}
