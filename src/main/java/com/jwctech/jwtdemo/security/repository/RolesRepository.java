package com.jwctech.jwtdemo.security.repository;

import com.jwctech.jwtdemo.security.models.ERole;
import com.jwctech.jwtdemo.security.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RolesRepository extends JpaRepository<Role,Long> {

    Optional<Role> findByName(ERole name);

}
