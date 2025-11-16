package com.innowise.authservice.dto;

import lombok.Builder;

@Builder
public record TokenValidationResponse(
        boolean valid,
        Long userId,
        String email,
        String role,
        String message
) {

    public static TokenValidationResponse valid(Long userId, String email, String role) {
        return TokenValidationResponse.builder()
                .valid(true)
                .userId(userId)
                .email(email)
                .role(role)
                .build();
    }

    public static TokenValidationResponse invalid(String message) {
        return TokenValidationResponse.builder()
                .valid(false)
                .message(message)
                .build();
    }
}
