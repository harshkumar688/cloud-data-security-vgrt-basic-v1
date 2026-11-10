package com.vgrt.securecloud.controller;

import com.vgrt.securecloud.repository.AuditEventRepository;
import com.vgrt.securecloud.service.DashboardService;
import com.vgrt.securecloud.service.FileService;
import java.util.Map;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {
    private final FileService files;
    private final AuditEventRepository auditEvents;
    private final DashboardService dashboardService;

    public PageController(FileService files, AuditEventRepository auditEvents, DashboardService dashboardService) {
        this.files = files;
        this.auditEvents = auditEvents;
        this.dashboardService = dashboardService;
    }

    private void populateAuthModel(Authentication auth, Model model, String activeNav) {
        boolean isAuthenticated = auth != null && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken);
        model.addAttribute("isAuthenticated", isAuthenticated);
        model.addAttribute("activeNav", activeNav);
        if (isAuthenticated) {
            model.addAttribute("username", auth.getName());
            model.addAttribute("isAdmin", auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
            model.addAttribute("files", files.listOwned(auth.getName()));
        } else {
            model.addAttribute("isAdmin", false);
        }
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/")
    public String home(Authentication auth, Model model) {
        populateAuthModel(auth, model, "home");
        return "index";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication auth, Model model) {
        populateAuthModel(auth, model, "dashboard");
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        Map<String, Object> data = dashboardService.getDashboardData(auth.getName());
        model.addAllAttributes(data);
        return "dashboard";
    }

    @GetMapping("/about")
    public String about(Authentication auth, Model model) {
        populateAuthModel(auth, model, "about");
        return "about";
    }

    @GetMapping("/methodology")
    public String methodology(Authentication auth, Model model) {
        populateAuthModel(auth, model, "methodology");
        return "methodology";
    }

    @GetMapping("/architecture")
    public String architecture(Authentication auth, Model model) {
        populateAuthModel(auth, model, "architecture");
        return "architecture";
    }

    @GetMapping("/vault")
    public String vault(Authentication auth, Model model) {
        populateAuthModel(auth, model, "vault");
        return "home";
    }

    @GetMapping("/admin/audit")
    public String audit(Authentication auth, Model model) {
        if (auth != null) {
            model.addAttribute("username", auth.getName());
            model.addAttribute("isAdmin", true);
        }
        model.addAttribute("activeNav", "audit");
        model.addAttribute("events", auditEvents.findTop100ByOrderByOccurredAtDesc());
        return "audit";
    }
}
