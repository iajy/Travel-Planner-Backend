package com.travelplanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.travelplanner.dto.BookingRequest;
import com.travelplanner.entity.Itinerary;
import com.travelplanner.repository.ItineraryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.util.*;

@Service
public class ItineraryService {

    @Autowired
    private ItineraryRepository repository;

    public Itinerary create(Itinerary itinerary) {
        itinerary.setLastUpdated(LocalDate.now());
        return repository.save(itinerary);
    }

    public List<Itinerary> get(long id) {
        return repository.findByUserId(id);
    }

    public Optional<Itinerary> getByShareToken(String token) {
        return repository.findByShareToken(token);
    }

    public List<Itinerary> getAll() {
        return repository.findAll();
    }

    public Itinerary update(Itinerary itinerary) {
        itinerary.setLastUpdated(LocalDate.now());
        return repository.save(itinerary);
    }

    public void delete(UUID id) {
        repository.deleteById(id);
    }

    public Itinerary duplicate(UUID id) {
        Itinerary original = repository.findById(id).orElseThrow();
        Itinerary copy = new Itinerary();
        copy.setUserId(original.getUserId());
        copy.setTitle(original.getTitle() + " (Copy)");
        copy.setStartDate(original.getStartDate());
        copy.setEndDate(original.getEndDate());
        copy.setDestination(List.copyOf(original.getDestination()));
        copy.setInterests(List.copyOf(original.getInterests()));
        copy.setNotes(original.getNotes());
        copy.setCollaborators(List.copyOf(original.getCollaborators()));
        return repository.save(copy);
    }

    public String share(UUID id) {
        Itinerary itinerary = repository.findById(id).orElseThrow();
        String token = UUID.randomUUID().toString();
        itinerary.setShared(true);
        itinerary.setShareToken(token);
        repository.save(itinerary);
        return token;
    }

    public File exportToJson(UUID id) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Itinerary itinerary = repository.findById(id).orElseThrow();
        File file = File.createTempFile("itinerary-" + id, ".json");
        mapper.writeValue(file, itinerary);
        return file;
    }

    public Itinerary addBooking(UUID id, BookingRequest booking) {
        Itinerary itinerary = repository.findById(id).orElseThrow();
        List<String> bookings = itinerary.getBookings() != null ? itinerary.getBookings() : new ArrayList<>();
        bookings.add(String.format("%s booking via %s [%s]: %s",
                booking.type, booking.provider, booking.confirmationNumber, booking.details));
        itinerary.setBookings(bookings);
        return repository.save(itinerary);
    }

	public ItineraryRepository getRepository() {
		return repository;
	}

	public void setRepository(ItineraryRepository repository) {
		this.repository = repository;
	}
}
