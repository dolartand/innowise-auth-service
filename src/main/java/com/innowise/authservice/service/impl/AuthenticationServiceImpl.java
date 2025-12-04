package com.innowise.authservice.service.impl;

import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.client.dto.UserInfoDto;
import com.innowise.authservice.dto.*;
import com.innowise.authservice.entity.RefreshToken;
import com.innowise.authservice.entity.UserCredential;
import com.innowise.authservice.enums.Role;
import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.UserAlreadyExistsException;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.repository.UserCredentialRepository;
import com.innowise.authservice.security.JwtProps;
import com.innowise.authservice.security.JwtTokenProvider;
import com.innowise.authservice.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserServiceClient userServiceClient;
    private final UserCredentialRepository userCredentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProps  jwtProps;


    @Override
    @Transactional
    public AuthResponse register(RegisterRequest registerRequest) {
        log.info("Register request for user with email: {}", registerRequest.email());

        if (userCredentialRepository.existsByEmail(registerRequest.email())) {
            log.warn("User with email {} already exists", registerRequest.email());
            throw new UserAlreadyExistsException("User with email " + registerRequest.email() + " already exists");
        }

        CreateUserRequest createUserRequest = CreateUserRequest.builder()
                .name(registerRequest.name())
                .surname(registerRequest.surname())
                .birthDate(registerRequest.birthDate())
                .email(registerRequest.email())
                .active(true)
                .build();

        UserInfoDto createdUser;
        try {
            createdUser = userServiceClient.createUser(createUserRequest);
            log.info("Created user with email: {}", createdUser.email());
        } catch (Exception ex) {
            log.error("Error while creating user with email: {}, {}", registerRequest.email(), ex.getMessage());
            throw ex;
        }

        String passwordHash = passwordEncoder.encode(registerRequest.password());
        Role role = userCredentialRepository.count() == 0 ? Role.ADMIN : Role.USER; // First user is ADMIN by default

        UserCredential credential = UserCredential.builder()
                .userId(createdUser.id())
                .email(createdUser.email())
                .passwordHash(passwordHash)
                .role(role)
                .build();

        userCredentialRepository.save(credential);

        String accessToken = jwtTokenProvider.generateAccessToken(
                createdUser.id(), createdUser.email(), role
        );
        String refreshToken = jwtTokenProvider.generateRefreshToken(createdUser.id());

        saveRefreshToken(createdUser.id(), refreshToken);

        log.info("Successfully register user with email: {}", createdUser.email());

        return new AuthResponse(
                accessToken,
                refreshToken,
                createdUser.id(),
                registerRequest.email(),
                role.name(),
                jwtProps.getAccessTokenExpiration()
        );
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest loginRequest) {
        log.info("Login request for user with email: {}", loginRequest.email());

        UserCredential credential = userCredentialRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(loginRequest.password(), credential.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        try {
            UserInfoDto user = userServiceClient.getUserById(credential.getUserId());
            if (!user.active()) {
                throw new InvalidCredentialsException("User is not active");
            }
        } catch (InvalidCredentialsException e) {
            log.error("Failed to check users activity status: {}", e.getMessage());
            throw new InvalidCredentialsException("Failed to validate user credentials");
        }

        String accessToken = jwtTokenProvider.generateAccessToken(
                credential.getUserId(),
                credential.getEmail(),
                credential.getRole()
        );

        String refreshToken = jwtTokenProvider.generateRefreshToken(credential.getUserId());

        saveRefreshToken(credential.getUserId(), refreshToken);

        log.info("Successfully login for user with email: {}", loginRequest.email());

        return new AuthResponse(
                accessToken,
                refreshToken,
                credential.getUserId(),
                credential.getEmail(),
                credential.getRole().name(),
                jwtProps.getAccessTokenExpiration()
        );
    }

    @Override
    @Transactional
    public AuthResponse refreshAccessToken(RefreshTokenRequest refreshTokenRequest) {
        log.info("Refresh token request received");

        String token = refreshTokenRequest.refreshToken();

        if (!jwtTokenProvider.validateToken(token)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        String tokenType = jwtTokenProvider.getTokenType(token);
        if (!"refresh".equals(tokenType)) {
            throw new InvalidTokenException("Provided token is not a refresh token");
        }

        RefreshToken storedToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(storedToken);
            throw new InvalidTokenException("Refresh token expired");
        }

        Long userId = storedToken.getUserId();

        refreshTokenRepository.delete(storedToken);

        UserCredential credential = userCredentialRepository.findByUserId(userId)
                .orElseThrow(() -> new InvalidTokenException("User credentials not found"));

        String newAccessToken = jwtTokenProvider.generateAccessToken(
                userId,
                credential.getEmail(),
                credential.getRole()
        );
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(userId);

        saveRefreshToken(userId, newRefreshToken);

        log.info("Refresh successful: userId={}", userId);

        return new AuthResponse(
                newAccessToken,
                newRefreshToken,
                userId,
                credential.getEmail(),
                credential.getRole().name(),
                jwtProps.getAccessTokenExpiration()
        );
    }

    @Override
    public TokenValidationResponse validateToken(TokenValidationRequest tokenValidationRequest) {
        log.debug("Validate token request");

        String token = tokenValidationRequest.token();

        try {
            if (!jwtTokenProvider.validateToken(token)) {
                return TokenValidationResponse.invalid("Invalid token");
            }

            if (jwtTokenProvider.isTokenExpired(token)) {
                return TokenValidationResponse.invalid("Token expired");
            }

            Long userId =  jwtTokenProvider.getUserIdFromToken(token);
            String email = jwtTokenProvider.getEmailFromToken(token);
            Role role = jwtTokenProvider.getRoleFromToken(token);

            log.debug("Token validation successful");

            return TokenValidationResponse.valid(userId, email, role.name());
        } catch (Exception e) {
            return TokenValidationResponse.invalid("Token validation failed: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public void logout(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(refreshTokenRepository::delete);
    }

    private void saveRefreshToken(Long userId, String token) {
        refreshTokenRepository.deleteByUserId(userId);

        LocalDateTime expiresAt = LocalDateTime.now()
                .plus(jwtProps.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS.toChronoUnit());

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(token)
                .expiresAt(expiresAt)
                .build();

        refreshTokenRepository.save(refreshToken);
        log.debug("Refresh token saved: userId={}, expiresAt={}", userId, expiresAt);
    }
}