package com.ch.memberservice.member.oauth2;

import java.util.Map;

/*
Google OAuth2 사용자 정보 규격화 클래스
- 소셜 로그인 성공 후, 각 Provider(Google, Kakao 등)마다 서로 이름을 다르게 주기 때문에, 사용자 정보를
  우리 애플리케이션의 공통 인터페이스 형식으로 변환하기 위한 클래스.
- 이를 통해 Service 로직에서는 공급자 종류에 상관없이 동일한 방법으로 사용자 정보를 처리할 수 있음.
*/
public class GoogleUserInfo implements OAuth2UserInfo{
    // provider 데이터가 json 으로 전송되므로, 이 json 을 보관 할 java 객체는 바로 Map.
    private final Map<String, Object> attribute;

    public GoogleUserInfo(Map<String, Object> attribute) {
        this.attribute = attribute;
    }

    @Override
    public String provider() {
        return "google";
    }

    @Override
    public String openId() {
        Object sub = attribute.get("sub");  //  구글에선 Id를 sub 이라는 이름으로 줌.
        return String.valueOf(sub);
    }

    @Override
    public String email() {
        Object email = attribute.get("email");  //  구글에선 email은 email 이라는 이름으로 줌.
        return String.valueOf(email);
    }

    @Override
    public String name() {
        Object name = attribute.get("name");  //  구글에선 name은 name 이라는 이름으로 줌.
        return String.valueOf(name);
    }
}
