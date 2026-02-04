package com.ch.memberservice.member.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
@Getter
public class MemberuserDetails implements UserDetails {

    // 아래에 선언된 Member entity 의 정보를 UserDetails 로 옮기자. << 이게 목표.(스프링이 원하기 때문에, 스프링이 이해하는 엔터티로 변환)
    private final Member member;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));    // 아직 권한 고도화를 안 했으므로 이렇게 세팅. 추후에 권한 분리를 할 때 하나씩 추가해나가면 된다.
        // 지금은 권한은 db에서 불러오지 않고 하드코딩. 추후 db에서 member.getRole() 로 추가
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getHomepageId();
    }
}
