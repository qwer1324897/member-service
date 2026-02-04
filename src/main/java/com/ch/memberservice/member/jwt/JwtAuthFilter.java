package com.ch.memberservice.member.jwt;

import com.ch.memberservice.member.exception.JwtAuthenticationException;
import com.ch.memberservice.member.redis.RedisTokenStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 클라이언트에게 발급된 Access Token 을 검사하는 필터

// 앞으로는 JWT 를 발급받은 클라이언트가 매 요청마다 header 안에 Authorization 의 값으로 "Bearer sldk해시값asdlfkasjdf" 토큰을 지참하기 때문에
// 이 JWT 토큰이 유효하다면, 시큐리리의 SecurityContext 에 로그인 인증회원이라는 기록을 저장하고, 원래 클라이언트가 원했던 API 에 접근할 수 있도록 허용
// 만약 JWT 가 문제가 있을 경우, 에러 메세지 처리를 수행
@RequiredArgsConstructor
@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenStore redisTokenStore;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return "OPTIONS".equalsIgnoreCase(request.getMethod())
                || uri.startsWith("/api/auth/login")
                || uri.startsWith("/api/auth/logout")
                || uri.startsWith("/api/auth/refresh"); // 있다면
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 클라이언트의 헤더 추출
        String header = request.getHeader("Authorization");

        /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
         1) 토큰이 존재하는가?
        ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
        // 헤더에 Authorization 이 없으면 SecurityContext 에 로그인 인증회원이라는 기록을 저장하지 않으며
        // 아무것도 처리하지 않음
        if(header == null || !header.startsWith("Bearer ")) {   // 헤더가 없거나, Bearer 로 시작하지 않으면 Token이 유효하지 않다는 것.
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7).trim();

        /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
         2) 토큰이 유효한가?
        ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
        try {
            // 토큰 분해 및 검증
            Claims claims = jwtTokenProvider.getClaims(token);

            String tokenType = claims.get("tokenType", String.class);
            if(! "access".equals(tokenType)) {
                throw new JwtAuthenticationException("Access Token 아님.");
            }

            /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
             3) 블랙리스트에 등록되어 있는가?
            ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
            String accessJti = claims.getId();

             if (accessJti !=null && redisTokenStore.isAccessTokenBlacklisted(accessJti)) { // null 이 아니고, 블랙리스트에 등록되어있지 않다면
                 // 이 에러 정보를 클라이언트도 알아야 하므로, 추후 에러 응답처리 할 예정
                 throw new JwtAuthenticationException("사용할 수 없는 토큰(블랙리스트)");
             }

             // 유효한 토큰을 가진 사람이므로, 서버의 api 를 접근할 수 있도록 스프링 시큐리리에게 인증이 성공된 회원이라고 알려주자.
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);    // 이제, 원래 요청했던 api 로 접근하게 해줌

        } catch (ExpiredJwtException e) {
            // 기간 만료된 토큰
            throw new JwtAuthenticationException("만료된 토큰입니다.");
        } catch (JwtException | IllegalArgumentException e) {
            // 위/변조, 형식 오류, 서명 불일치 등
            // 클라이언트에 적절한 메세지 출력
            throw new JwtAuthenticationException("유효하지 않은 인증 정보입니다.");
        }
    }


}
