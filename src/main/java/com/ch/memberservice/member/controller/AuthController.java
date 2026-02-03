package com.ch.memberservice.member.controller;

import com.ch.memberservice.member.dto.LoginResponse;
import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.entity.MemberuserDetails;
import com.ch.memberservice.member.jwt.JwtTokenProvider;
import com.ch.memberservice.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    // 회원 임시 등록 (db에 비밀번호를 암호화하여 넣기)
    @PostMapping("/temp")
    public ResponseEntity<?> tempRegist(MemberRequest memberRequest) {    // 프론트에서 json이 아니라 form 형식으로 날렸기 때문에 MemberRequest 로 바로 받을 수 있ㅇ,ㅁ
                                                                                                        // 만약 json으로 보낸다? 그럼 Responsebody 로 받으면 됨 ㅇㅇ
        log.debug("homepageId  는 {} ", memberRequest.getHomepageId());
        log.debug("password  는 {}", memberRequest.getPassword());
        log.debug("name 은 {}", memberRequest.getName());

        return ResponseEntity.ok(memberService.regist(memberRequest));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     로그인 요청 처리.
     스프링 필터체인의 요청을 받는 UsernamePasswordAuthenticationFilter 를 거치지 않고
     직접 로그인 요청을 받아보자. -> AuthenticationManager 에게 직접 일을 시켜보기
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    @PostMapping("/login")
    public ResponseEntity<?> login(MemberRequest memberRequest) {

        log.debug("로그인 요청 시 homepageId  는 {} ", memberRequest.getHomepageId());
        log.debug("로그인 요청 시 password  는 {}", memberRequest.getPassword());

        // AuthenticationManager 호출

        // Authentication Token 을 구현한 구현체 - UsernamePasswordAuthenticationToken
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(memberRequest.getHomepageId(), memberRequest.getPassword()));
        MemberuserDetails memberuserDetails = (MemberuserDetails)authentication.getPrincipal();

        if(authentication==null) {
            log.debug("인증 실패 ㅜㅜ");
        }
        log.debug("인증 성공!!");

        // Access Token 발급
        String accessToken = jwtTokenProvider.createAccessToken(authentication);

        return ResponseEntity.ok(new LoginResponse(accessToken));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     로그인해야 서비스 받을 수 있는 보호된 API
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    @GetMapping("/me")
    public Map<String, Object> getMyInfo(Authentication authentication) {

        // Authentication 에 들어있는 Principal 을 꺼내와서 사용정보로 제공
        MemberuserDetails memberuserDetails = (MemberuserDetails) authentication.getPrincipal();

        return Map.of("name", memberuserDetails.getUsername());
    }

    @ExceptionHandler(AuthenticationException.class)    // 원래는 따로 만들어야되는데 지금은 일단 컨트롤러에다가;;
    public String handle(AuthenticationException e) {
        log.debug("\n\n인증 실패 ㅜㅜ");
        return e.getMessage();
    }
}