package com.innowise.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record TokenValidationRequest(
        @NotBlank(message = "Token is required")
        String token
) {
}
