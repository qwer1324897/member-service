package com.ch.memberservice.member.oauth2;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.jwt.JwtTokenProvider;
import com.ch.memberservice.member.jwt.RefreshCookieSupport;
import com.ch.memberservice.member.redis.RedisTokenStore;
import com.ch.memberservice.member.repository.MemberRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/*
[역할/목적]
  - OAuth2 인증 직후 호출되는 핸들러 클래스

1. OAuth2AthenticationToken 에서 사용할 값 결정.
2. Access Token, Refresh Token 발급
3.

*/
@RequiredArgsConstructor
@Component
public class OAuth2JwtSuccessHandler implements AuthenticationSuccessHandler {

    @Value("${app.jwt.refresh-exp-seconds}")
    private long refreshExpSeconds;
    @Value("${app.frontend-url}")
    private String frontendUrl;

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final RedisTokenStore redisTokenStore;
    private final RefreshCookieSupport refreshCookieSupport;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 만약 사용자 정보가 넘어오지 않는다면, 에러
        if (!(authentication instanceof OAuth2AuthenticationToken auth2AuthenticationToken)) {
            // Java 14부터 도입된 Pattern Matching for instanceof 문법. 타입 확인과 형변환을 동시에 해버림.
            // if문 안에서 타입을 체크함과 동시에 authentication 에 새로운 이름표(auth2AuthenticationToken)를 붙여준 것
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 authentication required");
            return;
        }
        String registrationId = auth2AuthenticationToken.getAuthorizedClientRegistrationId();   // provider 가져오기.

        Map<String, Object> attributes = ((OAuth2User)auth2AuthenticationToken.getPrincipal()).getAttributes();
        OAuth2UserInfo info = OAuth2UserInfoFactory.from(registrationId, attributes);   // provider 에 관계없이 OAuth2UserInfo 형식으로 가져오기. 여기서 원하는 걸 추출.

        // JWT 발급을 위해 DB에서 회원정보 가져오기
        Member member = memberRepository.findByProvider_ProviderNameAndOpenId(registrationId, info.openId()).orElseThrow(()-> new IllegalStateException("해당 사용자의 정보를 찾을 수 없습니다."));

        // Access JWT 발급
        String accessToken = jwtTokenProvider.createAccessToken(
                new UsernamePasswordAuthenticationToken(Long.toString(member.getMemberId()),null, List.of(new SimpleGrantedAuthority("ROLE_USER")))
        );

        // Refresh 발급
        String refreshToken = jwtTokenProvider.createRefreshToken(member.getMemberId());

        // Redis 저장
        // redis 에 저장하기 위해 필요한 jti 만들기
        String jti = jwtTokenProvider.getJti(refreshToken);

        // Redis 저장
        redisTokenStore.saveRefreshToken(member.getMemberId(), jti, refreshToken, refreshExpSeconds);

        // refresh token 을 전송할 쿠키 세팅
        refreshCookieSupport.setRefreshCookie(response, refreshToken);

        // 클라이언트 브라우저가 SNS 요청 자체를 비동기 방식이 아닌 location.href="" 로 접근하므로 (= 동기 방식)
        // 서버가 이에 대한 응답을 바디로 전송하면, 브라우저 화면에 데이터가 출력되어 버림.
        // 따라서 클라이언트가 비동기 방식으로 임시 코드를 요청하면, 서버가 잠시 보관하고 있었던 access token 을 발급하면 된다.

        // Access Token <-> 임시 code 교환
        String tempCode = UUID.randomUUID().toString(); // 임시 코드 생성

        // redis 에 저장되는 형식 = oauth2:code:UUID zlsdkgh2eoiteqo
        redisTokenStore.saveTempCode(tempCode, accessToken, 60);

        // 클라이언트로 하여금 지정한 URL 로 리다이렉트 하라고 명령
        response.setStatus(HttpServletResponse.SC_FOUND);  // 요청은 정상적으로 처리 되었으나, 응답 결과는 다른 URL 에 있으니, 그 URL 로 다시 요청해. 라는 뜻
        response.setHeader(HttpHeaders.LOCATION, frontendUrl+"/oauth/callback?tempCode=" + URLEncoder.encode(tempCode, StandardCharsets.UTF_8));

        // response.getWriter().write( registrationId+" access token is : " + accessToken);

    }
}
