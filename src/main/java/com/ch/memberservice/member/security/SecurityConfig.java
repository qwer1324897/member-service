package com.ch.memberservice.member.security;

import com.ch.memberservice.member.jwt.JwtAuthFilter;
import com.ch.memberservice.member.oauth2.CustomOAuth2UserService;
import com.ch.memberservice.member.oauth2.OAuth2JwtSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${app.frontend-url}")
    private String frontendUrl;

    private final JwtAuthFilter jwtAuthFilter;

    // OAuth2 관련 객체들 Bean 등록
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2JwtSuccessHandler oAuth2JwtSuccessHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        //CORS 정책을 담는 설정(허용할 출처/메서드(GET,POST...)/헤더 등) 객체
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(frontendUrl)); // 금지사항!!!!!!!!!!!!!! * 패턴금지
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        config.setAllowedHeaders(List.of("*")); //혹시 보안을 더 강화할 일이 있다면, 헤더를 지정하는게 좋다
        config.setAllowCredentials(true);// 만일 true로 주지 않으면, 브라우저가 쿠키를 보내지 않거나 응답을 막음. 지금의 경우, 토큰을 허용하지 않았으므로  false
        config.setMaxAge(3600L); //3600초 동안을 동일 조건이라면 preflight 를 매번 하지 않음

        //허용할 URI패턴   우리의 경우   /api/**
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**",  config);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, LoginSuccessHandler loginSuccessHandler) throws Exception {

        httpSecurity.cors(cors -> {});

        httpSecurity.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS,"/**").permitAll()
                        //.requestMatchers("/api/auth/login").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/auth2/**").permitAll()
                        .requestMatchers("/login/oauth2/**").permitAll()    // OAuth2 관련 요청 허용
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                );

        //폼로그인에 대한 설정
        httpSecurity.formLogin( form -> form.disable());
        httpSecurity.httpBasic(basic->basic.disable()); //스프링의 기본 로그인폼을 사용하지 않음

//        // 폼로그인에 대한 설정
//        httpSecurity.formLogin(form -> form
//                .usernameParameter("homepageId")
//                .passwordParameter("password")
//                .successHandler(loginSuccessHandler)    // Handler 만들 때 자료형도 맞추고, @Conmponent 애노테이션도 붙였기 때문에 @Bean 없이 바로 사용.
//        );

        // JWT 를 사용하기 때문에 Session 이 만들어져선 안 되기 때문에 자동으로 등록되는 Session 을 만들지 않게 설정.
        httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // OAuth2 로그인 설정 추가
        httpSecurity.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userinfo -> userinfo
                        .userService(customOAuth2UserService)
                ).successHandler(oAuth2JwtSuccessHandler)   // 로그인 성공 처리
        );

        // JWT 필터 등록
        httpSecurity.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
