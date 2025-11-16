package com.innowise.authservice.dto;

import lombok.Builder;

@Builder
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn,
        Long userId,
        String email,
        String role
) {
    public AuthResponse(String accessToken, String refreshToken, Long userId, String email, String role, Long expiresIn) {
        this(accessToken, refreshToken, "Bearer", expiresIn, userId, email, role);
    }
}
