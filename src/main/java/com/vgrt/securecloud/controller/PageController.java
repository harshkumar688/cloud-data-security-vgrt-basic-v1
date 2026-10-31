package com.vgrt.securecloud.controller;

import com.vgrt.securecloud.entity.AuditEvent;
import com.vgrt.securecloud.repository.AuditEventRepository;
import com.vgrt.securecloud.service.FileService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {
    private final FileService files;
    private final AuditEventRepository auditEvents;
    public PageController(FileService files, AuditEventRepository auditEvents) { this.files = files; this.auditEvents = auditEvents; }

    @GetMapping("/login") public String login() { return "login"; }
    @GetMapping("/")
    public String home(Authentication auth, Model model) {
        model.addAttribute("username", auth.getName());
        model.addAttribute("isAdmin", auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
        model.addAttribute("files", files.listOwned(auth.getName()));
        return "home";
    }

    @GetMapping("/admin/audit")
    public String audit(Model model) {
        model.addAttribute("events", auditEvents.findTop100ByOrderByOccurredAtDesc());
        return "audit";
    }
}
