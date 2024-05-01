package com.omwanda98.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.omwanda98.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
	//query method to find user by username
	Optional<User> findByUsername(String username);

}
