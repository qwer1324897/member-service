package com.ch.memberservice.member.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

// entity 는 보호해야 되니까, 로그인 이후 응답할 정보를 담을 객체를 dto로 추가 선언.
@Getter @Setter
@AllArgsConstructor
public class LoginResponse {

    private String accessToken;
}
