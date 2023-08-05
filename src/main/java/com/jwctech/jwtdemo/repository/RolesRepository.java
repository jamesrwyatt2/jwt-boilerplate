package com.jwctech.jwtdemo.repository;

import com.jwctech.jwtdemo.models.ERole;
import com.jwctech.jwtdemo.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RolesRepository extends JpaRepository<Role,Long> {

    Optional<Role> findByName(ERole name);

}
