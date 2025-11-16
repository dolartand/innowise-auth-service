package com.innowise.authservice.service;

import com.innowise.authservice.dto.*;

public interface AuthenticationService {

    AuthResponse register(RegisterRequest registerRequest);

    AuthResponse login(LoginRequest loginRequest);

    AuthResponse refreshAccessToken(RefreshTokenRequest refreshTokenRequest);

    TokenValidationResponse validateToken(TokenValidationRequest tokenValidationRequest);

    void logout(String token);
}
