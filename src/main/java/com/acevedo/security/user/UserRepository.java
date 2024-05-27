package com.acevedo.security.user;

import java.util.Optional;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Integer> {
  Optional<User> findByEmail(String email);

  @Transactional
  @Modifying
  @Query("UPDATE User u SET u.firstname = :firstName, u.lastname = :lastName WHERE u.email = :email")
  public int updateByUsername(@Param("email") String email, @Param("firstName") String firstName, @Param("lastName") String lastName);

  @Query("SELECT u FROM User u WHERE u.verification = :verification")
  public User findByVerificationCode(@Param("verification") String verification);

  @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.email = :email")
  public Boolean verifyEmail(@Param("email") String email);

  @Query("SELECT u FROM User u WHERE u.passwordResetToken = :passwordResetToken")
  public Optional<User> findByPasswordResetToken(@Param("passwordResetToken") String passwordResetToken);
}
