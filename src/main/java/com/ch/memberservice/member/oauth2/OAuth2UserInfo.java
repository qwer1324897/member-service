package com.ch.memberservice.member.oauth2;

/*
구글 / 네이버 / 카카오 가 보내주는 사용자 정보를 우리 서비스에서 사용하기 쉽게(클린코딩 위함)
이 인터페이스를 이용한 정규화 과정을 거치면 추후 DefaultOAuth2UserService 작성 시 코드가 깔끔해짐
공통 부분을 보편화 즉, 정규화 시키자.
ex) google - sub, naver - response.id, kakao - id => 회사마다 id 값을 다 다르게 줌. 따라서 이걸 openid 라는 이름으로 통일(원하는 대로 지으면 됨)
*/
public interface OAuth2UserInfo {
    // 필수적인 추상메서드 정의
    String provider();
    String openId();
    String email();
    String name();
}
