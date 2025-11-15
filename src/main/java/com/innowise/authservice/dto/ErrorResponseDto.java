package com.innowise.authservice.dto;

import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

@Builder
public record ErrorResponseDto(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        String path,
        List<ValidationErrorDto> validationExceptions
) {
    @Builder
    public record ValidationErrorDto(
            String field,
            String rejectedValue,
            String message
    ) {

    }
}
