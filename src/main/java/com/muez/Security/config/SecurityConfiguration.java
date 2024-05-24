package com.muez.Security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // Disable CSRF protection
                .authorizeHttpRequests(authorizeHttpRequests -> {
                    authorizeHttpRequests
                            .requestMatchers("/api/v1/auth/*")
                            .permitAll()  // Allow public access to authentication endpoints
                            .anyRequest().authenticated();  // Require authentication for all other requests
                })
                .sessionManagement(sessionManagementCustomizer ->
                        sessionManagementCustomizer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // Use stateless sessions
                .authenticationProvider(authenticationProvider)  // Set custom authentication provider
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);  // Add JWT filter before UsernamePasswordAuthenticationFilter

        return http.build();
    }
}
