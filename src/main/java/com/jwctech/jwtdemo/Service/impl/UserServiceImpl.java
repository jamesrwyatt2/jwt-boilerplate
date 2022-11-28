package com.jwctech.jwtdemo.Service.impl;

import com.jwctech.jwtdemo.Service.UserService;
import com.jwctech.jwtdemo.config.SecurityConfig;
import com.jwctech.jwtdemo.entity.User;
import com.jwctech.jwtdemo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static java.lang.String.format;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public String createUser(User user) {
//        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "User Created";
    }

    @Override
    public User loadUserByUsername(String username)  {
        return userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException(format("User with username %s was not found", username)));
    }
}
