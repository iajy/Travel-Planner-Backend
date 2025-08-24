package com.travelplanner.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import com.travelplanner.service.AmadeusAuthService;


@RestController
@RequestMapping("/api/flights")
@CrossOrigin(origins = "https://travel-planner-frontend-flax.vercel.app")
public class FlightController {

  @Autowired
  private AmadeusAuthService authService;

  private final RestTemplate restTemplate = new RestTemplate();

  @GetMapping
  public ResponseEntity<?> getFlights(
      @RequestParam String origin,
      @RequestParam String destination,
      @RequestParam String departureDate,
      @RequestParam(required = false) String returnDate,
      @RequestParam(defaultValue = "1") int adults,
      @RequestParam(defaultValue = "0") int children) {

    StringBuilder url = new StringBuilder("https://test.api.amadeus.com/v2/shopping/flight-offers")
        .append("?originLocationCode=").append(origin)
        .append("&destinationLocationCode=").append(destination)
        .append("&departureDate=").append(departureDate)
        .append("&adults=").append(adults);

    if (children > 0) {
      url.append("&children=").append(children);
    }

    if (returnDate != null && !returnDate.isEmpty()) {
      url.append("&returnDate=").append(returnDate);
    }

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(authService.getAccessToken());

    HttpEntity<String> entity = new HttpEntity<>(headers);

    ResponseEntity<String> response = restTemplate.exchange(
        url.toString(),
        HttpMethod.GET,
        entity,
        String.class
    );

    return ResponseEntity.ok(response.getBody());
  }

  @GetMapping("/location")
  public ResponseEntity<?> getLocationName(@RequestParam String iataCode) {
    String url = "https://test.api.amadeus.com/v1/reference-data/locations"
        + "?subType=AIRPORT"
        + "&keyword=" + iataCode;

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(authService.getAccessToken());

    HttpEntity<String> entity = new HttpEntity<>(headers);

    ResponseEntity<String> response = restTemplate.exchange(
        url,
        HttpMethod.GET,
        entity,
        String.class
    );

    return ResponseEntity.ok(response.getBody());
  }

  @GetMapping("/iata")
  public ResponseEntity<?> getIataCode(@RequestParam String keyword) {
    String url = "https://test.api.amadeus.com/v1/reference-data/locations"
        + "?keyword=" + keyword
        + "&subType=AIRPORT";

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(authService.getAccessToken());

    HttpEntity<String> entity = new HttpEntity<>(headers);

    ResponseEntity<String> response = restTemplate.exchange(
        url,
        HttpMethod.GET,
        entity,
        String.class
    );

    return ResponseEntity.ok(response.getBody());
  }
}
