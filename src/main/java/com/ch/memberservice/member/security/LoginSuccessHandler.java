package com.ch.memberservice.member.security;

import com.ch.memberservice.member.entity.MemberuserDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

// 회원이 인증된 후, UsernamePasswordAuthenticationFilter 에 의해 성공 시 호출되는 핸들러
// 개발자는 로그인 성공 메세지 처리
@Slf4j
@Component  // Config 에서 @Bean 등록할 필요 없음
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        MemberuserDetails memberuserDetails = (MemberuserDetails) authentication.getPrincipal();
        log.debug("\n\n성공! 유저 이름은: {}", memberuserDetails.getUsername());

        response.getWriter().write(memberuserDetails.getUsername() + "님 로그인 성공");
    }
}
