package com.innowise.authservice.client.dto;

import lombok.Builder;

import java.time.LocalDate;

@Builder
public record UserInfoDto (
        Long id,
        String name,
        String surname,
        LocalDate birthDate,
        String email,
        Boolean active
) {

}
