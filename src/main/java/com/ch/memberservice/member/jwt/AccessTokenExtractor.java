package com.ch.memberservice.member.jwt;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

import java.util.Optional;

// 엑세스 토큰 추출하는 클래스.
// 엑세스 토큰 추출하는 걸 굉장히 자주 쓰기 때문에 그 때마다 if문으로 하드코딩하지말고 이걸 사용
public class AccessTokenExtractor {

    private  AccessTokenExtractor() {}

    public static Optional<String> extractBearerToken(HttpServletRequest request) {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 헤더에 Authorization 이 없으면 SecurityContext 에 로그인 인증회원이라는 기록을 저장하지 않으며
        // 아무것도 처리하지 않음
        if (header == null || !header.startsWith("Bearer ")) {   // 헤더가 없거나, Bearer 로 시작하지 않으면 Token이 유효하지 않다는 것.
            return Optional.empty(); // 토큰이 없는 경우
        }

        return Optional.of(header.substring("Bearer ".length()).trim());
    }
}
