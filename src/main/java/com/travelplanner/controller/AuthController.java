package com.travelplanner.controller;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.travelplanner.config.JwtUtils;
import com.travelplanner.entity.AppUser;
//import com.travelplanner.entity.UserDto;
import com.travelplanner.repository.UserRepository;
import com.travelplanner.service.EmailService;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "https://travel-planner-frontend-flax.vercel.app") //
public class AuthController {
    @Autowired private EmailService emailService;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private UserRepository userRepository;
    @Autowired private JwtUtils jwtUtils;

    private final Map<String, String> otpStorage = new ConcurrentHashMap<>();

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody Map<String ,String> payload) {
        String email = payload.get("email");
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);
        otpStorage.put(email, otp);
        emailService.sendOtpEmail(email, otp);
        return ResponseEntity.ok("OTP sent to email");
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String otp = payload.get("otp");

        String savedOtp = otpStorage.get(email);
        if (savedOtp != null && savedOtp.equals(otp)) {
            otpStorage.remove(email);
            return ResponseEntity.ok("OTP verified. You can now register.");
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP");
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        System.out.println(email);
        String username = payload.get("username");
        String password = payload.get("password");

        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest().body("Email already in use");
        }

        AppUser user = new AppUser();
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        
        user.setRoles(List.of("USER"));

        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData) {
        String email = loginData.get("email");
        String password = loginData.get("password");

        AppUser user = userRepository.findByEmail(email).orElse(null);
        
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        String token = jwtUtils.generateToken(user);
        System.out.println(user.getId());
        return ResponseEntity.ok(Map.of("token", token,"username", user.getUsername(),"userId",user.getId()));
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(Authentication authentication) {
        AppUser user = (AppUser) authentication.getPrincipal();
        return ResponseEntity.ok(Map.of(
            "email", user.getEmail(),
            "username", user.getUsername(),
            "roles", user.getRoles()
        ));
    }
    
    @GetMapping("/user-role")
    public ResponseEntity<?> getUserRoleById(@RequestParam Long userId) {
        AppUser user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        return ResponseEntity.ok(user.getRoles());
    }
    
    @GetMapping("/all-users")
    public ResponseEntity<List<AppUser>> getAllUsers() {
        List<AppUser> users = userRepository.findAll();
        
        // Map each user to a UserDto
        List<AppUser> userDtos = users.stream().map(user -> {
            AppUser dto = new AppUser();
            dto.setId(user.getId());
            dto.setUsername(user.getUsername());
            dto.setEmail(user.getEmail());
            dto.setRoles(user.getRoles());
            // add other safe fields...
            return dto;
        }).toList();
        
        return ResponseEntity.ok(userDtos);
    }
    
    @DeleteMapping("/delete-user/{id}")
    public ResponseEntity <?> deleteUser(@PathVariable  Long id){
    	
    	AppUser user = userRepository.findById(id).orElse(null);
    	if(user==null) {
    		return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
    	}
    	userRepository.delete(user);
    	return ResponseEntity.ok("User deleted");
    	
    }


}

