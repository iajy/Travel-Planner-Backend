package com.travelplanner.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.travelplanner.dto.BookingRequest;
import com.travelplanner.entity.Itinerary;
import com.travelplanner.service.ItineraryService;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/itineraries")
@CrossOrigin(origins = "https://travel-planner-frontend-flax.vercel.app")
public class ItineraryController {

    @Autowired
    private ItineraryService service;

    @PostMapping
    public ResponseEntity<Itinerary> create(@RequestBody Itinerary itinerary) {
        return ResponseEntity.ok(service.create(itinerary));
    }

    @GetMapping("/{id}")
    public ResponseEntity<List<Itinerary>> get(@PathVariable long id) {
//    	System.out.println("Received ID: " + id);
        List<Itinerary> itineraries = service.get(id);
        return ResponseEntity.ok(itineraries);
    }

    @GetMapping("/share/{token}")
    public ResponseEntity<Itinerary> getByShareToken(@PathVariable String token) {
        Optional<Itinerary> itinerary = service.getByShareToken(token);
        return itinerary.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<Itinerary> getAll() {
        return service.getAll();
    }

    @PutMapping("/{id}")
    public ResponseEntity<Itinerary> update(@PathVariable UUID id, @RequestBody Itinerary updated) {
        updated.setId(id);
        return ResponseEntity.ok(service.update(updated));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        service.delete(id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/duplicate")
    public ResponseEntity<Itinerary> duplicate(@PathVariable UUID id) {
        return ResponseEntity.ok(service.duplicate(id));
    }

    @PostMapping("/{id}/share")
    public ResponseEntity<String> share(@PathVariable UUID id) {
        String token = service.share(id);
        return ResponseEntity.ok(token);
    }

    @GetMapping("/{id}/export")
    public ResponseEntity<FileSystemResource> export(@PathVariable UUID id) throws IOException {
        File file = service.exportToJson(id);
        return ResponseEntity.ok(new FileSystemResource(file));
    }

    @PostMapping("/{id}/booking")
    public ResponseEntity<Itinerary> addBooking(@PathVariable UUID id, @RequestBody BookingRequest request) {
        return ResponseEntity.ok(service.addBooking(id, request));
    }
}

