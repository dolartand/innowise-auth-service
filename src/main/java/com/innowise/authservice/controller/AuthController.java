package com.innowise.authservice.controller;

import com.innowise.authservice.dto.*;
import com.innowise.authservice.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    /**
     * Register new user
     * @param request data for registration
     * @return tokens for access
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Register request, email: {}", request.email());

        AuthResponse response = authenticationService.register(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    /**
     * Log in user
     * @param request data for log in
     * @return tokens for access
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request, email: {}", request.email());

        AuthResponse response = authenticationService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Update access token by refresh token
     * @param request refresh token
     * @return new tokens for access
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Refresh token request received");

        AuthResponse response = authenticationService.refreshAccessToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Validate token
     * @param request token for validation
     * @return result of validation
     */
    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validate(@Valid @RequestBody TokenValidationRequest request) {
        log.debug("Validate token request received");

        TokenValidationResponse response = authenticationService.validateToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Log out user (delete refresh token)
     * @param request refresh token
     * @return status 204
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout request received");

        authenticationService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
