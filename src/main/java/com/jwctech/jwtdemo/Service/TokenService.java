package com.jwctech.jwtdemo.Service;

import com.jwctech.jwtdemo.entity.Role;

import java.util.Set;

public interface TokenService {

    public String generateToken(String username, Set<Role> roles);

    public String parseToken(String token);

    boolean validateToken(String token);

    public String refreshToken(String token);

}
