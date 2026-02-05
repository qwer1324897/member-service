package com.ch.memberservice.member.repository;

import com.ch.memberservice.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // 회원의 홈페이지 아이디만으로 회원정보를 가져오기 위한 메서드. JPA 에서 기본으로 지원해주지 않기 때문에 직접 만듬
    Optional<Member> findByHomepageId(String homepageId);

    /*이미 회원가입 되어 있는지 조회
    select * from member m join provider p
    on m.provider_id = p.provider_id
    and open_id = ?
    이 쿼리문 대신,
    */
    Optional<Member> findByProvider_ProviderNameAndOpenId(String providerName, String openId);


}
