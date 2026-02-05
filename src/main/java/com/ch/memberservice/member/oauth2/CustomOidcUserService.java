package com.ch.memberservice.member.oauth2;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.Provider;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.repository.ProviderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

// 구글용 서비스 메서드
@Service
@RequiredArgsConstructor
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private final ProviderRepository providerRepository;
    private final MemberRepository memberRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        OidcUser oidcUser = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        String openId = oidcUser.getSubject();  // OIDC 표준 고유 식별자 : sub
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName();

        // provider 생성. registrationId 는 그냥 String 일 뿐이므로, Provider entity 를 직접 만들어야 한다.
        Provider provider = providerRepository.findByProviderName(registrationId).orElseThrow(()-> new OAuth2AuthenticationException("잘못된 provider 입니다."));

        // 회원 가입(우리 db에 회원이 없을 때만. 이걸 먼저 체크 후 저장)
        // Optional에서 지원하는 orElseGet() 메서드는 메서드 앞에가 true 면 그걸 쓰고, false 면  orElseGet() 안의 람다를 실행하여 그 결과를 사용함.
        Member member = memberRepository.findByProvider_ProviderNameAndOpenId(registrationId, openId)
                .orElseGet(() -> memberRepository.save(Member.createOAuth2(name, email, openId, provider)));

        return oidcUser;
    }
}