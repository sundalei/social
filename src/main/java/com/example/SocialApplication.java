package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@EnableWebSecurity
public class SocialApplication {

    private static final Logger LOG = LoggerFactory.getLogger(SocialApplication.class);

    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal,
                                    CsrfToken csrfToken) {

        String authenticated = principal.getAttribute("name");
        LOG.info("user method is invoked with principal {}", authenticated);

        Map<String, Object> map = new HashMap<>();
        map.put("name", authenticated);
        map.put("token", csrfToken.getToken());
        map.put("tokenHeader", csrfToken.getHeaderName());
        return map;
    }

    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/", "/index.html", "/error", "/webjars/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .oauth2Login(Customizer.withDefaults())
                .logout(l -> l.logoutSuccessUrl("/").permitAll())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        // https://www.linkedin.com/pulse/solving-invalid-csrf-token-found-error-spring-security-oyeleye
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()));

        return http.build();
    }

}
