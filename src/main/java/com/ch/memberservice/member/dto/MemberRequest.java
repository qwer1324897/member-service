package com.ch.memberservice.member.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

// entity 는 보호되어야 하므로 파라미터 등에 쓰지 않기 때문에,
// 파라미터나 응답정보를 처리하기 위한 별도의 DTO를 정의.
@Getter @Setter
@AllArgsConstructor
// Setter만 사용하면 객체를 만든 후 setHomepageId(), setPassword()를 일일이 호출해야 함.
// 생성자도 사용하면 new MemberRequest("qwer", "1234", "홍길동")처럼 객체 생성과 동시에 필요한 모든 데이터를 한 번에 강제로 주입할 수 있어,
// 데이터가 빠진 "빈 껍데기" 객체가 돌아다니는 것을 방지
public class MemberRequest {
    private String homepageId;
    private String password;
    private String name;
}
