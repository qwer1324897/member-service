package com.ch.memberservice.member.oauth2;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo{
    // provider 데이터가 json 으로 전송되므로, 이 json 을 보관 할 java 객체는 바로 Map.
    private final Map<String, Object> response;

    // naver 는 json 안에 response 라는 json 을 하나 더 만들어서 그 안에 정보를 줌. 그래서 그걸 생성자로 처리하자.
    public NaverUserInfo(Map<String, Object> response) {
        Object res = response.get("response");

        this.response = (Map<String, Object>) res;
    }

    @Override
    public String provider() {
        return "naver";
    }

    @Override
    public String openId() {
        Object id = response.get("id");
        return String.valueOf(id);
    }

    @Override
    public String email() {
        Object email = response.get("email");
        return String.valueOf(email);
    }

    @Override
    public String name() {
        Object name = response.get("name");
        return String.valueOf(name);
    }
}
