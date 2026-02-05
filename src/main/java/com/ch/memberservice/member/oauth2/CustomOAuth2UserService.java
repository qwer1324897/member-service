package com.ch.memberservice.member.oauth2;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.Provider;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.repository.ProviderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
[역할/목적]
    - OAuth2 로그인 과정에서 UserInfo 를 기반으로 우리 서비스의 회원과 연결(가입/조회)하고,
    이후 Security 가 사용할 OAuth2User 를 반환해야 한다.
*/
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final ProviderRepository providerRepository;
    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 회원 가입을 위한 provider 정보 추출
        String registrationId = userRequest.getClientRegistration().getRegistrationId();    // google, naver, kakao
        // 구글은 지원 객체 형식이 다르므로 따로 해줘야 됨. 따라서 구글이면 걸러주자. << ai는 구글까지 커버하니까 안 해도 된다는데 뭔질 모르겠네;;
        if ("google".equals(registrationId)) {
            return super.loadUser(userRequest);
        }

        OAuth2UserInfo info = OAuth2UserInfoFactory.from(registrationId, oAuth2User.getAttributes());

        // provider 생성. registrationId 는 그냥 String 일 뿐이므로, Provider entity 를 직접 만들어야 한다.
        Provider provider = providerRepository.findByProviderName(registrationId).orElseThrow(()-> new OAuth2AuthenticationException("잘못된 provider 입니다."));

        // 회원 가입(우리 db에 회원이 없을 때만. 이걸 먼저 체크 후 저장)
        // Optional에서 지원하는 orElseGet() 메서드는 메서드 앞에가 true 면 그걸 쓰고, false 면  orElseGet() 안의 람다를 실행하여 그 결과를 사용함.
        Member member = memberRepository.findByProvider_ProviderNameAndOpenId(registrationId, info.openId())
                .orElseGet(() -> memberRepository.save(Member.createOAuth2(info.name(), info.email(), info.openId(), provider)));

        // 아래에서 반환하는 DefaultOAuth2User 는 폼로그인 방식에서 UserDetails에 해당. 즉, 로그인 성공 시 Security 가 만드는 Authentication token 의 principal 에 들어감.
        // 아래 파라미터에는 권한, 개발자가 넣을 정보, key(=openId) 를 넣는다.
        // 권한 가져오기
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        // 넣을 정보 가져오기. Map 형태로 넣어야 함
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes()); // sub, response.id, id 만 존재하지 openid 는 없음. 따라서 직접 넣기.
        attributes.put("openId", info.openId());    // 개발자가 정의한 key - value 추가.
        attributes.put("provider", info.provider());
        return new DefaultOAuth2User(authorities, attributes, "openId");
    }
}