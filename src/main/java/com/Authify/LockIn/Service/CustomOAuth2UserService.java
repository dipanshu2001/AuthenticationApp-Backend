package com.Authify.LockIn.Service;

import com.Authify.LockIn.Entity.UserEntity;
import com.Authify.LockIn.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        if (email == null) {
            throw new RuntimeException("Email not found in OAuth2 user attributes");
        }

        UserEntity user=userRepository.findByEmail(email).orElseGet(() -> {
            UserEntity newUser = UserEntity.builder()
                    .email(email)
                    .name(name)
                    .userID(UUID.randomUUID().toString())
                    .isAccountVerified(true)
                    .password("") // no password for Google users
                    .role("ROLE_USER") // default role for OAuth users
                    .build();
            return userRepository.save(newUser);
        });
        System.out.println("OAuth2 User created/loaded: " + email + ", role: " + user.getRole());
        return oAuth2User;
    }
}
