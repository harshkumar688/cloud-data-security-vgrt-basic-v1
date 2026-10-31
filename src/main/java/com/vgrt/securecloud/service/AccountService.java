package com.vgrt.securecloud.service;

import com.vgrt.securecloud.entity.UserAccount;
import com.vgrt.securecloud.repository.UserAccountRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    private final UserAccountRepository users;
    private final PasswordEncoder encoder;
    private final AuditService audit;

    public AccountService(UserAccountRepository users, PasswordEncoder encoder, AuditService audit) {
        this.users = users; this.encoder = encoder; this.audit = audit;
    }

    public void register(String username, String password) {
        String normalized = username == null ? "" : username.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{2,39}"))
            throw new IllegalArgumentException("Use 3–40 letters, numbers, dots, underscores or hyphens for your username.");
        if (password == null || password.length() < 12 || password.length() > 72)
            throw new IllegalArgumentException("Password must be between 12 and 72 characters.");
        if (users.existsByUsername(normalized)) throw new IllegalArgumentException("That username is already registered.");
        users.save(new UserAccount(normalized, encoder.encode(password)));
        audit.record(normalized, "REGISTRATION", null, "SUCCESS", "Account created");
    }
}
