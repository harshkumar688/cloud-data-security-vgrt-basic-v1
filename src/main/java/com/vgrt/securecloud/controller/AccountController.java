package com.vgrt.securecloud.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.vgrt.securecloud.service.AccountService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Controller
public class AccountController {
    private final AccountService accounts;
    public AccountController(AccountService accounts) { this.accounts = accounts; }

    @GetMapping("/register") public String form(Model model) { model.addAttribute("registration", new RegistrationForm()); return "register"; }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("registration") RegistrationForm form, BindingResult errors, RedirectAttributes flash) {
        if (!errors.hasErrors()) {
            try {
                accounts.register(form.username, form.password);
                flash.addFlashAttribute("success", "Account created. You can now sign in.");
                return "redirect:/login";
            } catch (IllegalArgumentException ex) { errors.reject("registration", ex.getMessage()); }
        }
        return "register";
    }

    public static class RegistrationForm {
        @NotBlank @Size(max = 80) public String username;
        @NotBlank @Size(min = 12, max = 72) public String password;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}
