package com.Authify.LockIn.Service;

import com.Authify.LockIn.Entity.RefreshToken;
import com.Authify.LockIn.Repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService{
    private final RefreshTokenRepository refreshTokenRepository;
    private static final long REFRESH_TOKEN_VALIDITY = 7L * 24 * 60 * 60 * 1000;
    @Override
    public RefreshToken createRefreshToken(String userId) {
        String randomToken = UUID.randomUUID().toString() + UUID.randomUUID();

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(randomToken)
                .expiresAt(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY)
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public Optional<RefreshToken> validateRefreshToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .filter(rt -> !rt.isRevoked())
                .filter(rt -> rt.getExpiresAt() >= System.currentTimeMillis());
    }

    @Override
    public void revokeToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
        });
    }

    @Override
    public void revokeAllForUser(String userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }
}
