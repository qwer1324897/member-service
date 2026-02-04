package com.ch.memberservice.member.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

@Component
public class RefreshCookieSupport {

    @Value("${app.jwt.refresh-exp-seconds}") private long refreshExpSeconds;
    @Value("${app.jwt.refresh-cookie-path}") private String path;
    @Value("${app.jwt.refresh-cookie-secure}") private boolean secure;
    @Value("${app.jwt.refresh-cookie-sameSite}") private String sameSite;

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     refresh token 용 쿠키 생성 (쿠키는 자바스크립트에서만 할 수 있는 게 아님)
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public void setRefreshCookie(HttpServletResponse httpServletResponse, String refreshToken) {
        ResponseCookie responseCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)  // 이 속성을 true 로 지정한 쿠키는 이 쿠키가 클라이언트에 전송되었을 경우, js 로 접근이 불가능
                .secure(secure)  // https 를 쓸거면 true. 근데 지금은 인증서 구매 안 한 거지기 때문에 http 로 접속. 따라서 false..
                .path(path)  // 웹브라우저가 요청 URL 이 /api/auth 로 시작할 때만 쿠키를 허용해서 서버로 자동 전송 (/api/auth/** 와 같다.)
                .maxAge(Duration.ofSeconds(refreshExpSeconds))
                .sameSite(sameSite)
                // 1. Strict(엄격한) - 브라우저가 같은 사이트 요청에서만 쿠키를 서버로 보냄
                // 2. Lax(해이한) - 일부 안전한 요청에서만 쿠키를 서버로 보냄(안전한 요청이라면, 다른 사이트로도 보냄)
                // 3. None - 모든 크로스 사이드 요청에서도 쿠키를 서버로 보냄. 이 땐 secure 를 true(=https)로 놓아야 한다.
                .build();

        // 헤더에 쿠키 추가
        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     refresh token 용 쿠키 삭제 - 쿠키는 삭제하는 방법이 따로 없으며 그냥 maxAge=0 으로 내려주면 됨. 즉, 만료 지시
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public void deleteRefreshCookie(HttpServletResponse httpServletResponse) {
        ResponseCookie responseCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(secure)
                .path(path)
                .maxAge(Duration.ZERO)
                .sameSite(sameSite)
                .build();
        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     refresh token 꺼내기
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public Optional<String> readCookie(HttpServletRequest httpServletRequest, String name) { // 쿠키가 여러개이기 때문에 원하는 걸 꺼내기 위해 name 을 파라미터로 받음
        Cookie[] cookies = httpServletRequest.getCookies();
        if(cookies == null) return Optional.empty();

        return Arrays.stream(cookies)
                .filter(cookie -> name.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
