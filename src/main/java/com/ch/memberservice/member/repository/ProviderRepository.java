package com.ch.memberservice.member.repository;

import com.ch.memberservice.member.entity.Provider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface ProviderRepository extends JpaRepository<Provider, Integer> {
    // provider 공급자 이름(google, kakao 등)으로 provider 엔티리를 찾기 위한 메서드 추가
    // 회원가입 및 로그인 시점에 해당 유저가 어떤 경로로 들어왔는지 DB에 기록(연결)해야 하기 때문

    Optional<Provider> findByProviderName(String providerName);  // 우린 providerName 으로 찾지만 Security 에서는 공급자를 registrationId 로 넘겨줌 이건 정해진 것.
    // JPA 모든 칼럼에 대한 메서드를 제공하지 않는 대신, JAP 내부적으로 정해놓은 규칙대로 메서드를 정의해야 동작함.
}

