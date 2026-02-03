package com.ch.memberservice.member.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, LoginSuccessHandler loginSuccessHandler) throws Exception {

        httpSecurity.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS,"/**").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/api/auth/temp").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                );

        // 폼로그인에 대한 설정
        httpSecurity.formLogin(form -> form
                .usernameParameter("homepageId")
                .passwordParameter("password")
                .successHandler(loginSuccessHandler)    // Handler 만들 때 자료형도 맞추고, @Conmponent 애노테이션도 붙였기 때문에 @Bean 없이 바로 사용.
        );

        return httpSecurity.build();
    }
}
