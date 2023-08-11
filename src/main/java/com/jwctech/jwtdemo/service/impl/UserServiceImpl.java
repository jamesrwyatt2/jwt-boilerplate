package com.jwctech.jwtdemo.service.impl;

import com.jwctech.jwtdemo.models.ERole;
import com.jwctech.jwtdemo.models.Role;
import com.jwctech.jwtdemo.service.UserService;
import com.jwctech.jwtdemo.models.User;
import com.jwctech.jwtdemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

import static java.lang.String.format;

@Service
public class UserServiceImpl implements UserService {


    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder =  passwordEncoder;
    }

    public String createUser(User user) {

//        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setEnabled(true);
//        Set<Role> addRoles = new HashSet<>();
//        Role role = new Role(ERole.USER);
//        addRoles.add(role);
//        user.setRoles(addRoles);
        User newUser = userRepository.save(user);


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
