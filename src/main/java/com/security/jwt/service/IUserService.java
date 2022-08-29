package com.security.jwt.service;

import com.security.jwt.entity.User;

import java.util.Optional;

public interface IUserService {
    Integer saveUser(User user);
    Optional<User> findByUserName(String username);
}
