package com.ch.memberservice.member.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter // 세터는 필요없기도 하고, 보안상 중요하기 때문에 게터만 만들자.
@Table(name = "member")
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private Long memberId;

    @Column(name = "homepage_id")
    private String homepageId;

    @Column(name = "password")
    private String password;

    @Column(name = "name")
    private String name;

    public Member(String homepageId, String password, String name) {
        this.homepageId = homepageId;
        this.password = password;
        this.name = name;
    }
    // Setter만 사용하면 객체를 만든 후 setHomepageId(), setPassword()를 일일이 호출해야 함.
    // 생성자를 사용하면 new MemberRequest("qwer", "1234", "홍길동")처럼 객체 생성과 동시에 필요한 모든 데이터를 한 번에 넣기 가능.

}
