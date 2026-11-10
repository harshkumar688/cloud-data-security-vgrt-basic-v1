package com.vgrt.securecloud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.vgrt.securecloud.repository.UserAccountRepository;
import com.vgrt.securecloud.security.LoginAuditHandlers;

@Configuration
public class SecurityConfig {
    @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(12); }

    @Bean UserDetailsService userDetailsService(UserAccountRepository users) {
        return username -> users.findByUsername(username.toLowerCase(java.util.Locale.ROOT))
                .map(account -> User.withUsername(account.getUsername()).password(account.getPasswordHash())
                        .roles(account.getRole()).build())
                .orElseThrow(() -> new org.springframework.security.core.userdetails.UsernameNotFoundException("User not found"));
    }

    @Bean DaoAuthenticationProvider authenticationProvider(UserDetailsService users, PasswordEncoder encoder) {
        var provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        return provider;
    }

    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http, LoginAuditHandlers handlers) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/overview",
                                "/about",
                                "/methodology",
                                "/architecture",
                                "/architecture-diagram.svg",
                                "/login",
                                "/register",
                                "/app.css",
                                "/app.js",
                                "/sample-output.html",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/error"
                        ).permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").successHandler(handlers).failureHandler(handlers).permitAll())
                .logout(logout -> logout.logoutSuccessUrl("/login?logout"))
                .build();
    }
}
