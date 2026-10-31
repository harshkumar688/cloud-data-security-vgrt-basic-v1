package com.vgrt.securecloud.security;

import com.vgrt.securecloud.service.AuditService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class LoginAuditHandlers implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    private final AuditService audit;
    public LoginAuditHandlers(AuditService audit) { this.audit = audit; }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth)
            throws IOException, ServletException {
        audit.record(auth.getName(), "LOGIN", null, "SUCCESS", "User authenticated");
        response.sendRedirect("/");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        org.springframework.security.core.AuthenticationException exception)
            throws IOException, ServletException {
        String attempted = request.getParameter("username");
        if (attempted != null) attempted = attempted.substring(0, Math.min(80, attempted.length()));
        audit.record(attempted, "LOGIN", null, "FAILURE", "Authentication failed");
        response.sendRedirect("/login?error");
    }
}
