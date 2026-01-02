package com.Authify.LockIn.Service;

import com.Authify.LockIn.Entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(String userId);
    Optional<RefreshToken> validateRefreshToken(String token);
    void revokeToken(String token);
    void revokeAllForUser(String userId);
}
