package com.vgrt.securecloud.controller;

import com.vgrt.securecloud.repository.AuditEventRepository;
import com.vgrt.securecloud.service.DashboardService;
import com.vgrt.securecloud.service.FileService;
import com.vgrt.securecloud.service.GovernanceService;
import com.vgrt.securecloud.service.RiskService;
import com.vgrt.securecloud.service.SecurityCenterService;
import java.util.Map;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PageController {
    private final FileService files;
    private final AuditEventRepository auditEvents;
    private final DashboardService dashboardService;
    private final SecurityCenterService securityCenterService;
    private final RiskService riskService;
    private final GovernanceService governanceService;

    public PageController(FileService files, AuditEventRepository auditEvents,
                          DashboardService dashboardService, SecurityCenterService securityCenterService,
                          RiskService riskService, GovernanceService governanceService) {
        this.files = files;
        this.auditEvents = auditEvents;
        this.dashboardService = dashboardService;
        this.securityCenterService = securityCenterService;
        this.riskService = riskService;
        this.governanceService = governanceService;
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

    @GetMapping("/risk")
    public String riskAssessment(Authentication auth, Model model,
                                 @RequestParam(value = "reassessed", required = false) String reassessed) {
        populateAuthModel(auth, model, "risk");
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        boolean isAdmin = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        Map<String, Object> riskData = riskService.assessRisk(auth.getName(), isAdmin);
        model.addAllAttributes(riskData);
        if ("true".equalsIgnoreCase(reassessed)) {
            model.addAttribute("reassessmentNotice", "Live posture recalculation complete. Deterministic score updated based on active audit telemetry.");
        }
        return "risk";
    }

    @PostMapping("/risk/reassess")
    public String triggerRiskReassessment(Authentication auth) {
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        riskService.triggerReassessment(auth.getName());
        return "redirect:/risk?reassessed=true";
    }

    @GetMapping("/governance")
    public String governance(Authentication auth, Model model) {
        populateAuthModel(auth, model, "governance");
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        boolean isAdmin = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        Map<String, Object> govData = governanceService.getGovernanceData(auth.getName(), isAdmin);
        model.addAllAttributes(govData);
        return "governance";
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
