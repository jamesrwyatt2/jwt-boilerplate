package com.jwctech.jwtdemo.service.impl;

import com.jwctech.jwtdemo.service.UserService;
import com.jwctech.jwtdemo.entity.User;
import com.jwctech.jwtdemo.repository.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.lang.String.format;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public String createUser(User user) {
        /**TODO: Password Encoder */
//        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setEnabled(true);
        User newUser = userRepository.save(user);
        System.out.println(newUser.toString());

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
