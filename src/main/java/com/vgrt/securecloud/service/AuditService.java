package com.vgrt.securecloud.service;

import com.vgrt.securecloud.entity.AuditEvent;
import com.vgrt.securecloud.repository.AuditEventRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {

    private static final String GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final AuditEventRepository events;

    public record AuditRecordDto(
            Long id,
            String timestamp,
            String actorUsername,
            String tenantWorkspace,
            String eventType,
            String outcome,
            String outcomeBadgeClass,
            String severity,
            String severityBadgeClass,
            String resourceId,
            String details,
            String recordHash,
            String previousHash,
            boolean isChainValid
    ) {}

    public record ChainVerificationReport(
            boolean isVerified,
            int totalBlocksEvaluated,
            String rootHash,
            String latestBlockHash,
            String statusMessage,
            String verifiedAtFormatted
    ) {}

    public record AuditPageResult(
            List<AuditRecordDto> records,
            int currentPage,
            int totalPages,
            int pageSize,
            long totalElements,
            ChainVerificationReport chainReport
    ) {}

    public AuditService(AuditEventRepository events) {
        this.events = events;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public synchronized void record(String actor, String type, String resourceId, String outcome, String details) {
        String safeActor = actor != null ? actor : "system";
        String safeType = type != null ? type : "GENERIC_EVENT";
        String safeResource = resourceId != null ? resourceId : "N/A";
        String safeOutcome = outcome != null ? outcome : "SUCCESS";
        String safeDetails = details != null ? details : "";

        // Find previous hash from the latest block in chain
        String prevHash = GENESIS_PREV_HASH;
        Optional<AuditEvent> lastOpt = events.findTop1ByOrderByIdDesc();
        if (lastOpt.isPresent() && lastOpt.get().getRecordHash() != null && !lastOpt.get().getRecordHash().isBlank()) {
            prevHash = lastOpt.get().getRecordHash();
        }

        Instant now = Instant.now();
        String recordHash = computeSha256(prevHash + "|" + safeActor + "|" + safeType + "|" + safeResource + "|" + safeOutcome + "|" + safeDetails + "|" + now.toEpochMilli());

        AuditEvent event = new AuditEvent(safeActor, safeType, safeResource, safeOutcome, safeDetails, prevHash, recordHash);
        events.save(event);
    }

    @Transactional
    public synchronized ChainVerificationReport verifyChainIntegrity() {
        List<AuditEvent> all = events.findAllByOrderByIdAsc();
        if (all.isEmpty()) {
            return new ChainVerificationReport(true, 0, GENESIS_PREV_HASH, GENESIS_PREV_HASH,
                    "Cryptographic chain is in genesis state. Zero mutations detected.",
                    TIME_FMT.format(Instant.now().atZone(ZoneId.systemDefault())));
        }

        String expectedPrevHash = GENESIS_PREV_HASH;
        String genesisRoot = "";

        for (int i = 0; i < all.size(); i++) {
            AuditEvent b = all.get(i);

            // Backfill legacy record if missing hash
            if (b.getRecordHash() == null || b.getPreviousHash() == null) {
                b.setPreviousHash(expectedPrevHash);
                String computed = computeSha256(expectedPrevHash + "|" + b.getActorUsername() + "|" + b.getEventType() + "|" + b.getResourceId() + "|" + b.getOutcome() + "|" + b.getDetails() + "|" + b.getOccurredAt().toEpochMilli());
                b.setRecordHash(computed);
                events.save(b);
            }

            if (i == 0) {
                genesisRoot = b.getRecordHash();
            }

            // Verify previous hash link
            if (!expectedPrevHash.equalsIgnoreCase(b.getPreviousHash())) {
                return new ChainVerificationReport(false, i + 1, genesisRoot, b.getRecordHash(),
                        "Chain linkage broken at Block #" + b.getId() + ": previousHash pointer does not match preceding block hash.",
                        TIME_FMT.format(Instant.now().atZone(ZoneId.systemDefault())));
            }

            // Recalculate block hash
            String calculated = computeSha256(b.getPreviousHash() + "|" + b.getActorUsername() + "|" + b.getEventType() + "|" + b.getResourceId() + "|" + b.getOutcome() + "|" + b.getDetails() + "|" + b.getOccurredAt().toEpochMilli());
            if (!calculated.equalsIgnoreCase(b.getRecordHash())) {
                return new ChainVerificationReport(false, i + 1, genesisRoot, b.getRecordHash(),
                        "Cryptographic digest mismatch at Block #" + b.getId() + ": payload hash does not match stored block signature.",
                        TIME_FMT.format(Instant.now().atZone(ZoneId.systemDefault())));
            }

            expectedPrevHash = b.getRecordHash();
        }

        String latestHash = all.get(all.size() - 1).getRecordHash();
        return new ChainVerificationReport(true, all.size(), genesisRoot, latestHash,
                "All " + all.size() + " blocks verified. Cryptographic hash chain is intact and non-repudiated.",
                TIME_FMT.format(Instant.now().atZone(ZoneId.systemDefault())));
    }

    public AuditPageResult queryAuditLogs(String currentUsername, boolean isAdmin,
                                          String query, String eventType, String outcome,
                                          String dateRange, int page, int pageSize) {
        // Ensure chain is verified
        ChainVerificationReport report = verifyChainIntegrity();

        List<AuditEvent> baseList = isAdmin ?
                events.findAllByOrderByIdDesc() :
                events.findAllByActorUsernameOrderByIdDesc(currentUsername);

        // Normalize filter inputs
        final String q = (query != null) ? query.trim().toLowerCase(Locale.ROOT) : "";
        final String filterType = (eventType != null && !eventType.equalsIgnoreCase("ALL")) ? eventType.trim().toUpperCase(Locale.ROOT) : "";
        final String filterOutcome = (outcome != null && !outcome.equalsIgnoreCase("ALL")) ? outcome.trim().toUpperCase(Locale.ROOT) : "";
        final String filterDate = (dateRange != null) ? dateRange.trim().toUpperCase(Locale.ROOT) : "ALL";

        Instant now = Instant.now();
        Instant cutoff = null;
        if ("TODAY".equals(filterDate)) {
            cutoff = now.minusSeconds(86400);
        } else if ("7DAYS".equals(filterDate)) {
            cutoff = now.minusSeconds(86400 * 7);
        } else if ("30DAYS".equals(filterDate)) {
            cutoff = now.minusSeconds(86400L * 30);
        }

        final Instant finalCutoff = cutoff;

        List<AuditRecordDto> filtered = new ArrayList<>();
        for (AuditEvent e : baseList) {
            // Date filter
            if (finalCutoff != null && e.getOccurredAt().isBefore(finalCutoff)) {
                continue;
            }
            // Event type filter
            if (!filterType.isEmpty() && !e.getEventType().equalsIgnoreCase(filterType)) {
                continue;
            }
            // Outcome filter
            if (!filterOutcome.isEmpty() && !e.getOutcome().equalsIgnoreCase(filterOutcome)) {
                continue;
            }
            // Query filter
            if (!q.isEmpty()) {
                String actor = e.getActorUsername() != null ? e.getActorUsername().toLowerCase(Locale.ROOT) : "";
                String typeStr = e.getEventType().toLowerCase(Locale.ROOT);
                String details = e.getDetails() != null ? e.getDetails().toLowerCase(Locale.ROOT) : "";
                String resId = e.getResourceId() != null ? e.getResourceId().toLowerCase(Locale.ROOT) : "";
                String idStr = String.valueOf(e.getId());

                if (!actor.contains(q) && !typeStr.contains(q) && !details.contains(q) && !resId.contains(q) && !idStr.contains(q)) {
                    continue;
                }
            }

            // Map severity and tenant
            String sev = determineSeverity(e.getEventType(), e.getOutcome());
            String sevBadge = sev.equals("CRITICAL") || sev.equals("HIGH") ? "badge-danger" :
                              sev.equals("MEDIUM") ? "badge-warning" : "badge-cipher";
            String outBadge = "SUCCESS".equalsIgnoreCase(e.getOutcome()) ? "badge-cipher" :
                              "DENIED".equalsIgnoreCase(e.getOutcome()) ? "badge-danger" : "badge-warning";

            String tenant = (e.getActorUsername() != null && !e.getActorUsername().isBlank()) ?
                    "tenant-" + e.getActorUsername() : "system-enclave";

            String ts = TIME_FMT.format(e.getOccurredAt().atZone(ZoneId.systemDefault()));

            filtered.add(new AuditRecordDto(
                    e.getId(),
                    ts,
                    e.getActorUsername() != null ? e.getActorUsername() : "system",
                    tenant,
                    e.getEventType(),
                    e.getOutcome(),
                    outBadge,
                    sev,
                    sevBadge,
                    e.getResourceId() != null ? e.getResourceId() : "N/A",
                    e.getDetails(),
                    e.getRecordHash() != null ? e.getRecordHash() : "UNHASHED",
                    e.getPreviousHash() != null ? e.getPreviousHash() : GENESIS_PREV_HASH,
                    report.isVerified()
            ));
        }

        // Pagination
        int safePageSize = Math.max(1, pageSize);
        int totalElements = filtered.size();
        int totalPages = (int) Math.ceil((double) totalElements / (double) safePageSize);
        if (totalPages == 0) totalPages = 1;

        int safePage = Math.max(1, Math.min(page, totalPages));
        int fromIndex = (safePage - 1) * safePageSize;
        int toIndex = Math.min(fromIndex + safePageSize, totalElements);

        List<AuditRecordDto> pageContent = (fromIndex < totalElements) ? filtered.subList(fromIndex, toIndex) : Collections.emptyList();

        return new AuditPageResult(pageContent, safePage, totalPages, safePageSize, totalElements, report);
    }

    private String determineSeverity(String eventType, String outcome) {
        if ("INTEGRITY_CHECK".equalsIgnoreCase(eventType) && "FAILURE".equalsIgnoreCase(outcome)) {
            return "CRITICAL";
        }
        if ("DENIED".equalsIgnoreCase(outcome)) {
            return "HIGH";
        }
        if ("LOGIN".equalsIgnoreCase(eventType) && "FAILURE".equalsIgnoreCase(outcome)) {
            return "HIGH";
        }
        if ("FAILURE".equalsIgnoreCase(outcome)) {
            return "MEDIUM";
        }
        if ("FILE_DELETE".equalsIgnoreCase(eventType) || "ROLE_UPDATE".equalsIgnoreCase(eventType)) {
            return "MEDIUM";
        }
        return "LOW";
    }

    public String exportToCsv(List<AuditRecordDto> records) {
        StringBuilder sb = new StringBuilder();
        sb.append("Event ID,Timestamp,Actor,Tenant,Event Type,Outcome,Severity,Resource ID,Details,Record Hash,Previous Hash\n");
        for (AuditRecordDto r : records) {
            sb.append(escapeCsv(String.valueOf(r.id()))).append(",");
            sb.append(escapeCsv(r.timestamp())).append(",");
            sb.append(escapeCsv(r.actorUsername())).append(",");
            sb.append(escapeCsv(r.tenantWorkspace())).append(",");
            sb.append(escapeCsv(r.eventType())).append(",");
            sb.append(escapeCsv(r.outcome())).append(",");
            sb.append(escapeCsv(r.severity())).append(",");
            sb.append(escapeCsv(r.resourceId())).append(",");
            sb.append(escapeCsv(r.details())).append(",");
            sb.append(escapeCsv(r.recordHash())).append(",");
            sb.append(escapeCsv(r.previousHash())).append("\n");
        }
        return sb.toString();
    }

    private String escapeCsv(String val) {
        if (val == null) return "\"\"";
        return "\"" + val.replace("\"", "\"\"") + "\"";
    }

    private String computeSha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm missing", e);
        }
    }
}
