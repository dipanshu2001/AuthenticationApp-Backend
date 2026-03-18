package com.Authify.LockIn.Service;

import com.Authify.LockIn.Entity.UserEntity;
import com.Authify.LockIn.IO.ProfileRequest;
import com.Authify.LockIn.IO.ProfileResponse;
import com.Authify.LockIn.IO.ProfileUpdateRequest;
import com.Authify.LockIn.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private static final int    MAX_OTP_ATTEMPTS  = 5;
    private static final long   OTP_VALIDITY_MS   = 15L * 60 * 1000;   // 15 minutes
    private static final long   VERIFY_VALIDITY_MS = 24L * 60 * 60 * 1000; // 24 hours

    private final UserRepository    userRepository;
    private final PasswordEncoder   passwordEncoder;
    private final EmailService      emailService;
    private final RefreshTokenService refreshTokenService;

    // ── Create ───────────────────────────────────────────────────────────────

    @Override
    public ProfileResponse createProfile(ProfileRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        }
        UserEntity saved = userRepository.save(convertToUserEntity(request));
        return convertToProfileResponse(saved);
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    @Override
    public ProfileResponse getProfile(String email) {
        return convertToProfileResponse(findByEmailOrThrow(email));
    }

    @Override
    public String getLoggedInUserId(String email) {
        return findByEmailOrThrow(email).getUserID();
    }

    @Override
    public String getEmailByUserId(String userId) {
        return userRepository.findByUserID(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId))
                .getEmail();
    }

    // ── Update ────────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public ProfileResponse updateProfile(String email, ProfileUpdateRequest request) {
        UserEntity user = findByEmailOrThrow(email);
        if (request.getName() != null && !request.getName().isBlank()) {
            user.setName(request.getName());
        }
        return convertToProfileResponse(userRepository.save(user));
    }

    // ── Password reset ────────────────────────────────────────────────────────
    //
    //  FIX: save OTP to DB *before* sending the email.
    //  Previously the email was sent first — if the save failed, the user
    //  received an OTP that would never validate.

    @Override
    @Transactional
    public void sendResetOTP(String email) {
        UserEntity user = findByEmailOrThrow(email);

        String otp        = generateOtp();
        long   expiryTime = System.currentTimeMillis() + OTP_VALIDITY_MS;

        // Persist first — if this throws the email is never sent
        user.setResetOtp(otp);
        user.setResetOtpExpiredAt(expiryTime);
        user.setResetOtpAttempts(0);
        userRepository.save(user);

        // Send after successful commit
        try {
            emailService.sendResetOTPEmail(user.getEmail(), otp);
        } catch (Exception e) {
            log.error("Failed to send reset OTP email to {}: {}", email, e.getMessage());
            throw new RuntimeException("Unable to send email");
        }
    }

    @Override
    @Transactional
    public void resetPassword(String email, String otp, String newPassword) {
        UserEntity user = findByEmailOrThrow(email);

        // FIX: brute-force protection — lock after MAX_OTP_ATTEMPTS failures
        if (user.getResetOtpAttempts() >= MAX_OTP_ATTEMPTS) {
            throw new RuntimeException("Too many incorrect attempts. Request a new OTP.");
        }

        if (user.getResetOtp() == null || !user.getResetOtp().equals(otp)) {
            user.setResetOtpAttempts(user.getResetOtpAttempts() + 1);
            userRepository.save(user);
            throw new RuntimeException("Invalid OTP");
        }

        if (user.getResetOtpExpiredAt() == null || user.getResetOtpExpiredAt() < System.currentTimeMillis()) {
            throw new RuntimeException("OTP expired");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetOtp(null);
        user.setResetOtpExpiredAt(null);
        user.setResetOtpAttempts(0);
        userRepository.save(user);
    }

    // ── Email verification ────────────────────────────────────────────────────
    //
    //  FIX: added @Transactional (was missing — writes had no rollback guarantee).
    //  FIX: save OTP before sending email, same reason as sendResetOTP.

    @Override
    @Transactional
    public void sendOTP(String email) {
        UserEntity user = findByEmailOrThrow(email);

        if (user.isAccountVerified()) {
            return;
        }

        String otp        = generateOtp();
        long   expiryTime = System.currentTimeMillis() + VERIFY_VALIDITY_MS;

        // Persist first
        user.setVerifyOtp(otp);
        user.setVerifyOtpExpiredAt(expiryTime);
        user.setVerifyOtpAttempts(0);
        userRepository.save(user);

        // Send after successful commit
        try {
            emailService.sendOtpEmail(user.getEmail(), otp);
        } catch (Exception e) {
            log.error("Failed to send verify OTP email to {}: {}", email, e.getMessage());
            throw new RuntimeException("Unable to send email");
        }
    }

    @Override
    @Transactional
    public void verifyOTP(String email, String otp) {
        UserEntity user = findByEmailOrThrow(email);

        // FIX: brute-force protection
        if (user.getVerifyOtpAttempts() >= MAX_OTP_ATTEMPTS) {
            throw new RuntimeException("Too many incorrect attempts. Request a new OTP.");
        }

        if (user.getVerifyOtp() == null || !user.getVerifyOtp().equals(otp)) {
            user.setVerifyOtpAttempts(user.getVerifyOtpAttempts() + 1);
            userRepository.save(user);
            throw new RuntimeException("Invalid OTP");
        }

        if (user.getVerifyOtpExpiredAt() == null || user.getVerifyOtpExpiredAt() < System.currentTimeMillis()) {
            throw new RuntimeException("OTP expired");
        }

        user.setAccountVerified(true);
        user.setVerifyOtp(null);
        user.setVerifyOtpExpiredAt(null);
        user.setVerifyOtpAttempts(0);
        userRepository.save(user);
    }

    // ── Security operations (moved from AuthController) ───────────────────────

    @Override
    @Transactional
    public void changePassword(String email, String currentPassword, String newPassword) {
        UserEntity user = findByEmailOrThrow(email);

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke all sessions so the user must re-authenticate everywhere
        refreshTokenService.revokeAllForUser(user.getUserID());
        log.info("Password changed for user {}", email);
    }

    @Override
    @Transactional
    public void deleteAccount(String email, String password) {
        UserEntity user = findByEmailOrThrow(email);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Password is incorrect");
        }

        userRepository.delete(user);
        log.info("Account deleted for user {}", email);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private UserEntity findByEmailOrThrow(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
    }

    private static String generateOtp() {
        return String.valueOf(ThreadLocalRandom.current().nextInt(100_000, 1_000_000));
    }

    private ProfileResponse convertToProfileResponse(UserEntity profile) {
        return ProfileResponse.builder()
                .name(profile.getName())
                .email(profile.getEmail())
                .userId(profile.getUserID())
                .isAccountVerified(profile.isAccountVerified())
                .build();
    }

    private UserEntity convertToUserEntity(ProfileRequest request) {
        return UserEntity.builder()
                .email(request.getEmail())
                .userID(UUID.randomUUID().toString())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .isAccountVerified(false)
                .resetOtpExpiredAt(null)
                .verifyOtp(null)
                .verifyOtpExpiredAt(null)
                .resetOtp(null)
                .role("ROLE_USER")
                .build();
    }
}