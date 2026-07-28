package com.example.api;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/users/{id}")
    public UserEntity getUser(@PathVariable Long id) {
        return UserRepository.findById(id);
    }

    @PostMapping("/users")
    public UserEntity updateUser(@RequestBody UserEntity user) {
        return UserRepository.save(user);
    }
}

@Entity
class UserEntity {
    @Id
    Long id;
    String email;
    String passwordHash;
    boolean isAdmin;
}

class UserRepository {
    static UserEntity findById(Long id) {
        return new UserEntity();
    }

    static UserEntity save(UserEntity user) {
        return user;
    }
}
