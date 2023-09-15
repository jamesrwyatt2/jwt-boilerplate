package com.jwctech.jwtdemo.security.config;

import com.jwctech.jwtdemo.security.jwt.authenticationJwtTokenFilter;
import com.jwctech.jwtdemo.security.jwt.RsaKeyProps;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    private final RsaKeyProps rsaKeys;

    @Value("${jwc.app.jwtCookieName}")
    private String jwtCookie;

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);

    public SecurityConfig(RsaKeyProps rsaKeys) {
        this.rsaKeys = rsaKeys;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                // Disable CSRF (cross site request forgery)
                .csrf(csrf -> csrf.disable())

                .authorizeRequests(auth -> auth
                        //Allow all request for home page with permit ALl
                        .requestMatchers().permitAll()
                        .mvcMatchers("/api/auth/**").permitAll()
                        .mvcMatchers("/secured/admin").hasAuthority("SCOPE_ADMIN")
                        //AnyRequest is a catch-all for any request that doesn't match the above
                        .anyRequest().authenticated()
                )
                // Custom JWT validation
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())
                        .authenticationEntryPoint((request, response, exception) -> {
                            validateToken(request);
                        })

                )
                //Set the session management to stateless
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .httpBasic().disable()
                .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey())
                .privateKey(rsaKeys.privateKey())
                .build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public authenticationJwtTokenFilter authenticationJwtTokenFilter()  throws Exception {
        return new authenticationJwtTokenFilter();
    }

    /**
     * This is triggered for endpoints that require authorization
     *
     * @param request
     */
    public void validateToken(HttpServletRequest request){
        LOG.info("Custom JWT validation");
        // Check if there are Cookies
        if(request.getCookies() != null && request.getCookies().length > 0) {
            // Filter cookies, find token
            String token = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(jwtCookie))
                    .findFirst().get().getValue();
            //Validate token
            jwtDecoder().decode(token);
        } else {
            // If no cookie are present, throw unauthorized error
            LOG.warn("Throw Error!!!");
        }

    }

}
