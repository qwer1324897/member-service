package com.ch.memberservice.member.dto;

// 토큰에다가 Member entity를 담은 UserDetails 를 그냥 보내버리면 비밀번호같은것도 안에 들어있어서 보안상 위험하기 때문에
// 응답용 클래스를 따로 만들어서 관리.

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
@AllArgsConstructor
public class MemberResponse {

    private String homepageId;
    private String name;
}
