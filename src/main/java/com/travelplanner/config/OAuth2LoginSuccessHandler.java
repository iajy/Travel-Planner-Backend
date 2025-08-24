package com.travelplanner.config;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.travelplanner.entity.AppUser;
import com.travelplanner.repository.UserRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        // Check if user exists in DB
        AppUser user = userRepository.findByEmail(email).orElse(null);

        // If user doesn't exist, create a new one
        if (user == null) {
            user = new AppUser();
            user.setEmail(email);
            user.setUsername(name != null ? name : email); // Use Google name or fallback to email
            user.setPassword(""); // No password needed for Google login
            user.setRoles(List.of("USER"));
            userRepository.save(user);
        }

        // Generate JWT
        String token = jwtUtils.generateToken(user);

        // Redirect to frontend with token and user info
        response.sendRedirect("https://travel-planner-frontend-flax.vercel.app/oauth2-success?token=" + token
        	    + "&userId=" + user.getId()
        	    + "&username=" + user.getUsername());

    }
}
