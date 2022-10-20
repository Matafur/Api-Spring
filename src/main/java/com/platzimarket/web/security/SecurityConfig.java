package com.platzimarket.web.security;

import com.platzimarket.domain.service.PlatziuserDetailsServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
public class SecurityConfig  {
    @Autowired
    private PlatziuserDetailsServices platziuserDetailsServices;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(platziuserDetailsServices);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.authorizeRequests().anyRequest().authenticated().and().formLogin().and().httpBasic().and().authenticationManager(authenticationManager);

        return http.build();
    }
}
