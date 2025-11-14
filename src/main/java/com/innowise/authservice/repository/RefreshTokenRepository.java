package com.innowise.authservice.repository;

import com.innowise.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    // Named methods

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUserId(Long userId);

    boolean existsByToken(String token);

    // JPQL

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.token = :token")
    int deleteByToken(@Param("token") String token);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    int deleteExpired(@Param("now") LocalDateTime now);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token < :now")
    List<RefreshToken> findExpired(@Param("now") LocalDateTime now);

    // Native sql

    @Query(value = "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = :userId AND expires_at > NOW()",
            nativeQuery = true)
    long countActiveTokensByUserId(@Param("userId") Long userId);
}
