package com.vgrt.securecloud.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "file_records")
public class FileRecord {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "owner_id", nullable = false)
    private UserAccount owner;
    @Column(nullable = false, length = 255)
    private String originalName;
    @Column(nullable = false, unique = true, length = 36)
    private String storageKey;
    @Column(nullable = false, length = 128)
    private String contentType;
    @Column(nullable = false)
    private long sizeBytes;
    @Column(nullable = false, length = 64)
    private String sha256;
    @Column(nullable = false, length = 32)
    private String nonceBase64;
    @Column(nullable = false, columnDefinition = "TEXT")
    private String wrappedKeyBase64;
    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected FileRecord() {}
    public FileRecord(UserAccount owner, String originalName, String storageKey, String contentType,
                      long sizeBytes, String sha256, String nonceBase64, String wrappedKeyBase64) {
        this.owner = owner; this.originalName = originalName; this.storageKey = storageKey;
        this.contentType = contentType; this.sizeBytes = sizeBytes; this.sha256 = sha256;
        this.nonceBase64 = nonceBase64; this.wrappedKeyBase64 = wrappedKeyBase64;
    }
    public Long getId() { return id; }
    public UserAccount getOwner() { return owner; }
    public String getOriginalName() { return originalName; }
    public String getStorageKey() { return storageKey; }
    public String getContentType() { return contentType; }
    public long getSizeBytes() { return sizeBytes; }
    public String getSha256() { return sha256; }
    public String getNonceBase64() { return nonceBase64; }
    public String getWrappedKeyBase64() { return wrappedKeyBase64; }
    public Instant getCreatedAt() { return createdAt; }
}
