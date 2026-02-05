package com.ch.memberservice.member.oauth2;

import java.util.Map;

public class KakaoUserInfo implements OAuth2UserInfo{

    private final Map<String, Object> attribute;

    public KakaoUserInfo(Map<String, Object> attribute) {
        this.attribute = attribute;
    }

    @Override
    public String provider() {
        return "kakao";
    }

    @Override
    public String openId() {
        Object id = attribute.get("id");
        return String.valueOf(id);
    }

    @Override
    public String email() {
        Object account = attribute.get("kakao_account");
        Object email = ((Map<String, Object>) account).get("email");
        return String.valueOf(email);
    }

    @Override
    public String name() {
        Object account = attribute.get("kakao_account");
        Object profile = ((Map<String, Object>) account).get("profile");
        Object nickname = ((Map<String, Object>) profile).get("nickname");
        return String.valueOf(nickname);
    }
}
