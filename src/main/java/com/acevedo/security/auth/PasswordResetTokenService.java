package com.acevedo.security.auth;

import com.acevedo.security.user.User;
import com.acevedo.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PasswordResetTokenService {
    private final UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    private long tokenValidityInSeconds = 3600;

    public String generateToken(User user) {
        String token = generateRandomString();
        // Save token to database (implementation shown later)
        System.out.println("countItems");
        System.out.println(token);
        saveTokenToUser(user, token);
        return token;
    }

    public String generateRandomString() {
        byte[] randomBytes = new byte[32]; // Adjust size as needed
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().encodeToString(randomBytes);
    }

    private void saveTokenToUser(User user, String token) {
        // Replace with your actual implementation to save token and expiry in database
        user.setPasswordResetToken(token);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusSeconds(tokenValidityInSeconds));
        // Call your user repository to save the updated user object
        userRepository.save(user);
    }

    public User validatePasswordResetToken(String token) {
        // Replace with your actual implementation to retrieve user by token from database
        System.out.println("validatePasswordResetToken");
        Optional<User> user = userRepository.findByPasswordResetToken(token);
        if (user.isPresent()) {
            LocalDateTime expiry = user.get().getPasswordResetTokenExpiry();
            if(expiry != null && expiry.isAfter(LocalDateTime.now())){
                System.out.println("expiry");
                return user.get();
            }
        }
        return user.get();
    }

    public void resetPassword(User user, String newPassword){
        // Use BCryptPasswordEncoder to set the hashed password
        System.out.println("setPassword");
        user.setPassword(passwordEncoder.encode(newPassword)); // Don't re-hash!

        user.setPasswordResetToken(null); System.out.println("setPasswordResetToken");
        user.setPasswordResetTokenExpiry(null);System.out.println("setPasswordResetTokenExpiry");
        userRepository.save(user);System.out.println("save");
    }
}
