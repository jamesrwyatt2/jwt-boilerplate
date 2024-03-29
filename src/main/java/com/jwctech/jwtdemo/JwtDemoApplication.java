package com.jwctech.jwtdemo;


import com.jwctech.jwtdemo.security.jwt.RsaKeyProps;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RsaKeyProps.class)
@SpringBootApplication
public class JwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtDemoApplication.class, args);
    }

}
