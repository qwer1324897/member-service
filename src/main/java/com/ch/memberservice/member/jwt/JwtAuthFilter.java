package com.ch.memberservice.member.jwt;

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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 클라이언트의 헤더 추출
        String header = request.getHeader("Authorization");

        // 헤더에 Authorization 이 없으면 SecurityContext 에 로그인 인증회원이라는 기록을 저장하지 않으며
        // 아무것도 처리하지 않음
        if(header == null || !header.startsWith("Bearer ")) {   // 헤더가 없거나, Bearer 로 시작하지 않으면 Token이 유효하지 않다는 것.
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰이 유효한 사용자의 경우
        String token = header.substring(7).trim();  // "Bearer " bearer 와 띄어쓰기 이후에 오는 7번째부터 시작하는 해시값 + 빈칸제거해서 깨끗한 hash 값을 추출.

        if(jwtTokenProvider.validateAccessToken(token)){
            // 스프링 시큐리리에게 이 요청은 유효한(로그인 인증을 받은) 것이라는 걸 알려줘야 함
            if(SecurityContextHolder.getContext().getAuthentication()==null) {  // ContextHolder 에 기존 인증이 null 이면(없다면)
                // jwtProvider 안에 jwt token 을 이용하여 Authentication Token 을 얻어오는 메서드가 준비되어 있음
                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);   // 이 등록을 하는 순간 스프링은 인증회원이라는 것을 인지함. 더 이상 막지 않음
                log.debug("필터 단계에서 JWT 검증 성공");
            }
        }
        filterChain.doFilter(request, response);

    }
}
