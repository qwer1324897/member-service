package com.ch.memberservice.member.oauth2;

/*
registration, 즉 provider 에 따라 적절한 UserInfo 구현체를 생성
이유, 장점 - CustomOAuth2UserService 코드가 공급자별로 if/else 를 사용하됨을 방지
*/

import java.util.Map;

public class OAuth2UserInfoFactory {
    private OAuth2UserInfoFactory() {}  // 인스턴스화 방지

    // 이 메서드를 호출하려면, 공급자명(google, naver, kakao) 그 공급자에 해당하는 맵 형태의 데이터를 넘겨야 한다.

    public static OAuth2UserInfo from(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "naver" -> new NaverUserInfo(attributes);
            case "kakao" -> new KakaoUserInfo(attributes);
            default -> throw new IllegalArgumentException("지원하지 않는 소셜 로그인 공급자입니다: " + registrationId);
        };
    }
}
