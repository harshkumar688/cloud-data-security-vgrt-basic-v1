package com.vgrt.securecloud.repository;

import com.vgrt.securecloud.entity.FileRecord;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FileRecordRepository extends JpaRepository<FileRecord, Long> {
    List<FileRecord> findAllByOwner_UsernameOrderByCreatedAtDesc(String username);
    Optional<FileRecord> findByIdAndOwner_Username(Long id, String username);
}
