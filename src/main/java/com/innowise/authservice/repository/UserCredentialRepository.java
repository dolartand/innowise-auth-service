package com.innowise.authservice.repository;

import com.innowise.authservice.entity.UserCredential;
import com.innowise.authservice.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, Long> {

    // Named methods

    Optional<UserCredential> findByEmail(String email);

    Optional<UserCredential> findByUserId(Long userId);

    boolean existsByEmail(String email);

    // JPQL

    @Modifying
    @Query("UPDATE UserCredential u SET u.role = :role WHERE u.userId = :userId")
    int updateRoleByUserId(@Param("userId") Long userId, @Param("role") Role role);

    @Modifying
    @Query("DELETE FROM UserCredential u WHERE u.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);

    // Native sql

    @Query(value = "SELECT email FROM user_credentials WHERE user_id = :userId", nativeQuery = true)
    String getEmailByUserId(@Param("userId") Long userId);
}
