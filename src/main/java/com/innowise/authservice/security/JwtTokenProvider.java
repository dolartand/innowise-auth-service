package com.innowise.authservice.security;

import com.innowise.authservice.enums.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtTokenProvider {

    private final JwtProps jwtProps;

    public String generateAccessToken(Long userId, String email, Role role) {
        log.debug("Generating access token for user {}, email {}, with role {}", userId, email,  role);

        Instant now = Instant.now();
        Instant expiration = now.plusMillis(jwtProps.getAccessTokenExpiration());

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);
        claims.put("role", role);
        claims.put("type", "access");

        String token = Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuer(jwtProps.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        log.debug("Access token generated successfully for user {}, email {}, with role {}", userId, email,  role);
        return token;
    }

    public String generateRefreshToken(Long userId) {
        log.debug("Generating refresh token for userId={}", userId);

        Instant now = Instant.now();
        Instant expiration = now.plusMillis(jwtProps.getRefreshTokenExpiration());

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("type", "refresh");

        String token = Jwts.builder()
                .claims(claims)
                .subject(String.valueOf(userId))
                .issuer(jwtProps.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        log.debug("Refresh token generated successfully for userId={}", userId);
        return token;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);

            log.debug("Token validated successfully");
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = extractAllClaims(token);
        Object userClaim = claims.get("userId");

        if (userClaim instanceof Integer) {
            return ((Integer) userClaim).longValue();
        } else if (userClaim instanceof Long) {
            return (Long) userClaim;
        }

        throw new IllegalArgumentException("Invalid token");
    }

    public String getEmailFromToken(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("email").toString();
    }

    public Role getRoleFromToken(String token) {
        Claims claims = extractAllClaims(token);
        String roleStr =  claims.get("role").toString();
        return Role.valueOf(roleStr);
    }

    public String getTokenType(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("type").toString();
    }

    public Date getExpirationDateFromToken(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getExpiration();
    }

    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtProps.getSecret().getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
