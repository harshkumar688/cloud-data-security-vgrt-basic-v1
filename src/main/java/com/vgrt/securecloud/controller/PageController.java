package com.vgrt.securecloud.controller;

import com.vgrt.securecloud.repository.AuditEventRepository;
import com.vgrt.securecloud.service.DashboardService;
import com.vgrt.securecloud.service.FileService;
import com.vgrt.securecloud.service.SecurityCenterService;
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
    private final SecurityCenterService securityCenterService;

    public PageController(FileService files, AuditEventRepository auditEvents,
                          DashboardService dashboardService, SecurityCenterService securityCenterService) {
        this.files = files;
        this.auditEvents = auditEvents;
        this.dashboardService = dashboardService;
        this.securityCenterService = securityCenterService;
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

    @GetMapping("/files")
    public String myFiles(Authentication auth, Model model) {
        populateAuthModel(auth, model, "files");
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        var fileList = files.listOwned(auth.getName());
        model.addAttribute("files", fileList);
        model.addAttribute("totalFiles", fileList.size());
        model.addAttribute("totalBytes", fileList.stream().mapToLong(f -> f.getSizeBytes()).sum());
        return "files";
    }

    @GetMapping("/vault")
    public String vaultRedirect() {
        return "redirect:/files";
    }

    @GetMapping("/upload")
    public String secureUpload(Authentication auth, Model model) {
        populateAuthModel(auth, model, "upload");
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        return "upload";
    }

    @GetMapping("/security")
    public String securityCenter(Authentication auth, Model model) {
        populateAuthModel(auth, model, "security");
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        Map<String, Object> secData = securityCenterService.getSecurityData(auth.getName());
        model.addAllAttributes(secData);
        return "security";
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
