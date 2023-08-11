package com.jwctech.jwtdemo.security.service.impl;

import com.jwctech.jwtdemo.security.service.UserService;
import com.jwctech.jwtdemo.security.models.User;
import com.jwctech.jwtdemo.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
