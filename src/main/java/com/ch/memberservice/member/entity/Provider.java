package com.ch.memberservice.member.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

// sns 플랫폼 로그인 엔터리
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)  // 내부적으로 호출하는 JPA 를 위한 설정.
// PROTECTED는 객체의 무결성 유지. JPA가 접근할 수 있는 최소한의 권한을 유지하면서, 외부에서의 무분별한 생성을 막는 안전장치
@Table(name = "provider")
public class Provider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "provider_id")
    private int providerId;

    @Column(name = "provider_name")
    private String providerName;

    // 정적 팩토리 메서드. (Static Factory Method)
    // 생성자 대신 의미 있는 이름을 가진 메서드를 사용하기 위해 객체를 생성한다.
    // + 캡슐화. 엔티티의 초기화 로직을 한곳에서 관리하고, 외부에는 완성된 객체만 던질 수 있다.
    public static Provider create(String providerName) {
        Provider p = new Provider();
        p.providerName = providerName;
        return p;
    }

}
