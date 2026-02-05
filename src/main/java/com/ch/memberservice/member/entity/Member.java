package com.ch.memberservice.member.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

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

    @Column(name = "open_id")
    private String openId;

    @Column(name = "name")
    private String name;

    @Column(name = "email")
    private String email;

    @Column(name = "phone")
    private String phone;

    @Column(name = "regdate")
    private LocalDateTime regdate;

    @Column(name = "updated")
    private LocalDateTime updated;

    @ManyToOne(fetch = FetchType.LAZY)  // LAZY 로 설정하면 연관되어있는 entity 를 바로 조회하지 않고, 필요할 때만 DB에서 가져옴
    // ex) memberRepository.findById() 호출을 해도 가져오지 않음. 나중에 getProvider() 호출 시 DB에서 가져옴.
    @JoinColumn(name = "provider_id")
    private Provider provider;

    public static Member create(String homepageId, String password, String name) {
        Member member = new Member();
        member.homepageId = homepageId;
        member.password = password;
        member.name = name;
        // 등록일 등 필요한 초기값 설정 가능
        return member; // null이 아니라 생성한 객체를 반환!
    }

    // OAuth2 회원가입용
    public static Member createOAuth2(String name, String email, String openId, Provider provider) {
        Member member = new Member();
        member.name = name;
        member.email = email;
        member.openId = openId; // 이 부분이 빠져있었습니다.
        member.provider = provider;
        return member;
    }

    public Member(String homepageId, String password, String name) {
        this.homepageId = homepageId;
        this.password = password;
        this.name = name;
    }
    // Setter만 사용하면 객체를 만든 후 setHomepageId(), setPassword()를 일일이 호출해야 함.
    // 생성자를 사용하면 new MemberRequest("qwer", "1234", "홍길동")처럼 객체 생성과 동시에 필요한 모든 데이터를 한 번에 넣기 가능.

}
