package com.Authify.LockIn.Config;

import com.Authify.LockIn.Entity.RefreshToken;
import com.Authify.LockIn.Entity.UserEntity;
import com.Authify.LockIn.Service.RefreshTokenService;
import com.Authify.LockIn.Util.JwtUtil;
import com.Authify.LockIn.Repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
private final RefreshTokenService refreshTokenService;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        if (email == null) {
            throw new RuntimeException("Email not found in OAuth2 user attributes");
        }

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("OAuth2 user not found: " + email));

        String jwtToken = jwtUtil.generateToken(
                org.springframework.security.core.userdetails.User
                        .withUsername(email)
                        .password("")
                        .authorities(user.getRole())
                        .build()
        );
        // ✅ Create refresh token (just like regular login)
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUserID());

        // ✅ Set JWT cookie
        ResponseCookie jwtCookie = ResponseCookie.from("jwt", jwtToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .sameSite("Strict")
                .build();

        // ✅ Set refresh token cookie
        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken.getToken())
                .httpOnly(true)
                .secure(true)
                .path("/auth")
                .maxAge(Duration.ofDays(7))  // ✅ Now OAuth users also stay logged in 7 days!
                .sameSite("Strict")
                .build();

        // Add both cookies
        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        response.sendRedirect("http://localhost:5173/oauth-success?token=" + jwtToken);
    }

}