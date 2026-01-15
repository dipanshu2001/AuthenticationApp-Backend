package com.Authify.LockIn.Config;

import com.Authify.LockIn.Entity.UserEntity;
import com.Authify.LockIn.Util.JwtUtil;
import com.Authify.LockIn.Repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("OAuth2 user not found: " + email));

        String jwtToken = jwtUtil.generateToken(
                org.springframework.security.core.userdetails.User
                        .withUsername(email)
                        .password("")
                        .authorities(user.getRole())
                        .build()
        );
        response.sendRedirect("http://localhost:5173/oauth-success?token=" + jwtToken);
    }

}