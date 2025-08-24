package com.travelplanner.controller;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.travelplanner.dto.TripRequest;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "https://travel-planner-frontend-flax.vercel.app")
public class TravelController {

	@Value("${OPENROUTER_API_KEY}")
    private String apiKey;

    @PostMapping("/generate-itinerary")
    public ResponseEntity<?> generateItinerary(@RequestBody TripRequest request) {
        try {
            String prompt = "You are a travel assistant. Plan a day-by-day travel itinerary for a trip to "
                    + request.destination + " from " + request.startDate + " to " + request.endDate + ". Interests: "
                    + (request.interests != null ? request.interests : "sightseeing") + ". "
                    + "Include must-see spots, food suggestions, and tips.";

            String requestBody = """
                {
                  "model": "mistralai/mistral-7b-instruct",
                  "messages": [
                    { "role": "user", "content": "%s" }
                  ]
                }
            """.formatted(prompt);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create("https://openrouter.ai/api/v1/chat/completions"))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .header("HTTP-Referer", "https://travel-planner-frontend-flax.vercel.app/")
                    .header("X-Title", "AI Trip Planner")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            // Convert to JSON and return parsed result
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(response.body());

            return ResponseEntity.ok(jsonNode);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("AI request failed: " + e.getMessage());
        }
    }
}
