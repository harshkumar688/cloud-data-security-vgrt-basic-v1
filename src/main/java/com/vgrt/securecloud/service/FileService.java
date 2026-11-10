package com.vgrt.securecloud.service;

import com.vgrt.securecloud.crypto.CryptoService;
import com.vgrt.securecloud.entity.FileRecord;
import com.vgrt.securecloud.repository.FileRecordRepository;
import com.vgrt.securecloud.repository.UserAccountRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class FileService {
    private static final long MAX_BYTES = 10L * 1024 * 1024;
    private final FileRecordRepository files;
    private final UserAccountRepository users;
    private final CryptoService crypto;
    private final AuditService audit;
    private final Path storageRoot;

    public FileService(FileRecordRepository files, UserAccountRepository users, CryptoService crypto,
                       AuditService audit, @Value("${vgrt.storage.root}") String storageRoot) {
        this.files = files; this.users = users; this.crypto = crypto; this.audit = audit;
        this.storageRoot = Path.of(storageRoot).toAbsolutePath().normalize();
    }

    public FileRecord upload(String username, String originalName, String contentType, byte[] content) throws Exception {
        if (content.length == 0) throw new IllegalArgumentException("Choose a file that is not empty.");
        if (content.length > MAX_BYTES) throw new IllegalArgumentException("Files must be 10 MB or smaller.");
        var owner = users.findByUsername(username).orElseThrow();
        String submittedName = (originalName == null ? "file" : originalName.replace('\\', '/'));
        String displayName = submittedName.substring(submittedName.lastIndexOf('/') + 1);
        displayName = displayName.replaceAll("[\\p{Cntrl}]", "_");
        if (displayName.isBlank()) displayName = "file";
        var encrypted = crypto.encrypt(content);
        String key = UUID.randomUUID().toString();
        Files.createDirectories(storageRoot);
        Path object = storageRoot.resolve(key + ".bin").normalize();
        if (!object.getParent().equals(storageRoot)) throw new SecurityException("Invalid storage key");
        try {
            Files.write(object, encrypted.ciphertext());
            String mediaType = contentType == null || !contentType.matches("[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+") || contentType.length() > 128
                    ? "application/octet-stream" : contentType;
            var saved = files.save(new FileRecord(owner, displayName, key, mediaType, content.length,
                    encrypted.sha256(), encrypted.nonceBase64(), encrypted.wrappedKeyBase64()));
            audit.record(username, "FILE_UPLOAD", saved.getId().toString(), "SUCCESS", "Encrypted file stored (AES-256-GCM)");
            return saved;
        } catch (Exception ex) {
            Files.deleteIfExists(object);
            audit.record(username, "FILE_UPLOAD", null, "FAILURE", "Upload failed");
            throw ex;
        }
    }

    public List<FileRecord> listOwned(String username) { return files.findAllByOwner_UsernameOrderByCreatedAtDesc(username); }

    public Optional<FileRecord> findOwnedById(String username, Long id) {
        return files.findByIdAndOwner_Username(id, username);
    }

    public DownloadedFile download(String username, Long id) throws Exception {
        var record = files.findByIdAndOwner_Username(id, username).orElse(null);
        if (record == null) {
            audit.record(username, "FILE_DOWNLOAD", String.valueOf(id), "DENIED", "File not found or not owned by user");
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "File not found");
        }
        try {
            Path object = storageRoot.resolve(record.getStorageKey() + ".bin").normalize();
            if (!object.getParent().equals(storageRoot)) throw new SecurityException("Invalid storage key");
            byte[] plaintext = crypto.decrypt(Files.readAllBytes(object), record.getNonceBase64(),
                    record.getWrappedKeyBase64(), record.getSha256());
            audit.record(username, "FILE_DOWNLOAD", id.toString(), "SUCCESS", "Authorized download completed (SHA-256 Verified)");
            return new DownloadedFile(record.getOriginalName(), record.getContentType(), plaintext);
        } catch (Exception ex) {
            audit.record(username, "FILE_DOWNLOAD", id.toString(), "FAILURE", "Decryption or integrity verification failed");
            throw ex;
        }
    }

    public boolean verifyIntegrity(String username, Long id) {
        var record = files.findByIdAndOwner_Username(id, username).orElse(null);
        if (record == null) {
            audit.record(username, "INTEGRITY_CHECK", String.valueOf(id), "DENIED", "Verification requested on non-existent file");
            return false;
        }
        try {
            Path object = storageRoot.resolve(record.getStorageKey() + ".bin").normalize();
            if (!object.getParent().equals(storageRoot) || !Files.exists(object)) {
                audit.record(username, "INTEGRITY_CHECK", id.toString(), "FAILURE", "Object ciphertext missing from disk");
                return false;
            }
            // Decrypt and match SHA-256 digest
            crypto.decrypt(Files.readAllBytes(object), record.getNonceBase64(),
                    record.getWrappedKeyBase64(), record.getSha256());
            audit.record(username, "INTEGRITY_CHECK", id.toString(), "SUCCESS", "SHA-256 digest re-verified against ciphertext tag");
            return true;
        } catch (Exception ex) {
            audit.record(username, "INTEGRITY_CHECK", id.toString(), "FAILURE", "Cryptographic integrity failure or corrupt tag");
            return false;
        }
    }

    public void delete(String username, Long id) throws Exception {
        var record = files.findByIdAndOwner_Username(id, username).orElse(null);
        if (record == null) {
            audit.record(username, "FILE_DELETE", String.valueOf(id), "DENIED", "Deletion attempted on non-existent file");
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "File not found");
        }
        try {
            Path object = storageRoot.resolve(record.getStorageKey() + ".bin").normalize();
            if (object.getParent().equals(storageRoot)) {
                Files.deleteIfExists(object);
            }
            files.delete(record);
            audit.record(username, "FILE_DELETE", id.toString(), "SUCCESS", "File ciphertext permanently purged from storage enclave");
        } catch (Exception ex) {
            audit.record(username, "FILE_DELETE", id.toString(), "FAILURE", "File purge operation failed");
            throw ex;
        }
    }

    public record DownloadedFile(String filename, String contentType, byte[] content) {}
}
