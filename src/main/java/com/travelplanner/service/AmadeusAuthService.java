package com.travelplanner.service;

import org.springframework.http.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;

@Service
public class AmadeusAuthService {

  private final String API_KEY = System.getenv("api_key");
  private final String API_SECRET = System.getenv("api_secret");
  private final String AUTH_URL = "https://test.api.amadeus.com/v1/security/oauth2/token";

  private String accessToken;
  private Instant expiryTime;

  public synchronized String getAccessToken() {
    // If token is still valid, return it
    if (accessToken != null && expiryTime != null && Instant.now().isBefore(expiryTime)) {
      return accessToken;
    }
    // Otherwise, refresh
    refreshAccessToken();
    return accessToken;
  }

  @Scheduled(fixedDelay = 25 * 60 * 1000) // Refresh every 25 minutes
  public synchronized void refreshAccessToken() {
    RestTemplate restTemplate = new RestTemplate();

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    String body = "grant_type=client_credentials"
        + "&client_id=" + API_KEY
        + "&client_secret=" + API_SECRET;

    HttpEntity<String> entity = new HttpEntity<>(body, headers);

    ResponseEntity<TokenResponse> response = restTemplate.exchange(
        AUTH_URL,
        HttpMethod.POST,
        entity,
        TokenResponse.class
    );

    if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
      accessToken = response.getBody().getAccess_token();
      int expiresIn = response.getBody().getExpires_in(); // seconds
      expiryTime = Instant.now().plusSeconds(expiresIn - 60); // refresh 1 min early
      System.out.println("Access token refreshed: " + accessToken);
    } else {
      throw new RuntimeException("Failed to refresh Amadeus access token");
    }
  }

  // Response DTO for Amadeus token API
  private static class TokenResponse {
    private String access_token;
    private int expires_in;

    public String getAccess_token() { return access_token; }
    public void setAccess_token(String access_token) { this.access_token = access_token; }

    public int getExpires_in() { return expires_in; }
    public void setExpires_in(int expires_in) { this.expires_in = expires_in; }
  }
}
