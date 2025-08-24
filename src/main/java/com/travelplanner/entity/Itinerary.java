package com.travelplanner.entity;

import jakarta.persistence.*;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;


@Entity
public class Itinerary {
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private UUID id;

	private long userId;
	private String username;
	private String title;
	private LocalDate startDate;
	private LocalDate endDate;

	

	private String notes;
	private LocalDate lastUpdated;
	private boolean isShared;
	private String shareToken;

	@ElementCollection
	private List<String> destination;

	@ElementCollection
	private List<String> interests;

	@ElementCollection
	private List<UUID> collaborators;

	@ElementCollection
	private List<String> bookings; // Booking details from external API

	// Getters and Setters

	public UUID getId() {
		return id;
	}

	public void setId(UUID id) {
		this.id = id;
	}

	public long getUserId() {
		return userId;
	}

	public void setUserId(long userId) {
		this.userId = userId;
	}
	
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public LocalDate getStartDate() {
		return startDate;
	}

	public void setStartDate(LocalDate startDate) {
		this.startDate = startDate;
	}

	public LocalDate getEndDate() {
		return endDate;
	}

	public void setEndDate(LocalDate endDate) {
		this.endDate = endDate;
	}

	public List<String> getDestination() {
		return destination;
	}

	public void setDestination(List<String> destination) {
		this.destination = destination;
	}

	public List<String> getInterests() {
		return interests;
	}

	public void setInterests(List<String> interests) {
		this.interests = interests;
	}

	public String getNotes() {
		return notes;
	}

	public void setNotes(String notes) {
		this.notes = notes;
	}

	public List<UUID> getCollaborators() {
		return collaborators;
	}

	public void setCollaborators(List<UUID> collaborators) {
		this.collaborators = collaborators;
	}

	public LocalDate getLastUpdated() {
		return lastUpdated;
	}

	public void setLastUpdated(LocalDate lastUpdated) {
		this.lastUpdated = lastUpdated;
	}

	public boolean isShared() {
		return isShared;
	}

	public void setShared(boolean shared) {
		isShared = shared;
	}

	public String getShareToken() {
		return shareToken;
	}

	public void setShareToken(String shareToken) {
		this.shareToken = shareToken;
	}

	public List<String> getBookings() {
		return bookings;
	}

	public void setBookings(List<String> bookings) {
		this.bookings = bookings;
	}

}