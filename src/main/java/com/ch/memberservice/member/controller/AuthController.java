package com.ch.memberservice.member.controller;

import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;

    // 회원 임시 등록 (db에 비밀번호를 암호화하여 넣기)
    @PostMapping("/temp")
    public ResponseEntity<?> tempRegist(MemberRequest memberRequest) {    // 프론트에서 json이 아니라 form 형식으로 날렸기 때문에 MemberRequest 로 바로 받을 수 있ㅇ,ㅁ

        log.debug("homepageId  는 {} ", memberRequest.getHomepageId());
        log.debug("password  는 {}", memberRequest.getPassword());
        log.debug("name 은 {}", memberRequest.getName());

        return ResponseEntity.ok(memberService.regist(memberRequest));
    }

}
