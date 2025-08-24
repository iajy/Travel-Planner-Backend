package com.travelplanner.config;

import java.sql.Date;

import org.springframework.stereotype.Component;

import com.travelplanner.entity.AppUser;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtils {
    private final String jwtSecret = "LYC30cWe4k99izzwqeo2PXcE5xiBFgm9o4by4z2VnYiL5yQIH3bv3UDnyKZD5PGmbofz9Q5CDNMN3QpEH21Vrg==";
    private final long jwtExpirationMs = 86400000;

    public String generateToken(AppUser user) {
        return Jwts.builder()
            .setSubject(user.getEmail())
            .claim("username", user.getUsername())
            .claim("roles", user.getRoles())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }

    public String getEmailFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwt(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}

