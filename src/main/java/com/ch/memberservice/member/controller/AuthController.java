package com.ch.memberservice.member.controller;

import com.ch.memberservice.member.dto.LoginResponse;
import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.dto.MemberResponse;
import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.MemberuserDetails;
import com.ch.memberservice.member.jwt.AccessTokenExtractor;
import com.ch.memberservice.member.jwt.JwtTokenProvider;
import com.ch.memberservice.member.jwt.RefreshCookieSupport;
import com.ch.memberservice.member.redis.RedisTokenStore;
import com.ch.memberservice.member.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenStore redisTokenStore;

    private final RefreshCookieSupport refreshCookieSupport;

    @Value("${app.jwt.refresh-exp-seconds}")
    private long refreshExpSeconds;

    // 회원 임시 등록 (db에 비밀번호를 암호화하여 넣기)
    @PostMapping("/temp")
    public ResponseEntity<?> tempRegist(MemberRequest memberRequest) {    // 프론트에서 json이 아니라 form 형식으로 날렸기 때문에 MemberRequest 로 바로 받을 수 있음
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
    public ResponseEntity<?> login(MemberRequest memberRequest, HttpServletResponse response) {

        log.debug("로그인 요청 시 homepageId  는 {} ", memberRequest.getHomepageId());
        log.debug("로그인 요청 시 password  는 {}", memberRequest.getPassword());

        // AuthenticationManager 호출

        // Authentication Token 을 구현한 구현체 - UsernamePasswordAuthenticationToken
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(memberRequest.getHomepageId(), memberRequest.getPassword()));
        MemberuserDetails memberuserDetails = (MemberuserDetails)authentication.getPrincipal();
        Member member = memberuserDetails.getMember();

        if(authentication==null) {
            log.debug("인증 실패 ㅜㅜ");
        }
        log.debug("인증 성공!!");

        // Access Token 생성
        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        // Refresh Token 생성
        String refreshToken = jwtTokenProvider.createRefreshToken(member.getMemberId());

        // Redis 에 저장.  우리가 직접 정의한 RedisTokenStore 의 메서드에 값 넣어주기.
        redisTokenStore.saveRefreshToken(member.getMemberId(), jwtTokenProvider.getJti(refreshToken), refreshToken, refreshExpSeconds);

        // 토큰 내려주기
        refreshCookieSupport.setRefreshCookie(response, refreshToken);

        return ResponseEntity.ok(new LoginResponse("Bearer " ,accessToken));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     로그아웃 요청 처리
     - 지금 가지고 있는 토큰이 정상이라면 전부 무효화하고,
        정상이 아니어도 그냥 로그아웃 요청만으로 성공으로 처리
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
         1) refresh 토큰이 존재하면, 폐기
        ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
        refreshCookieSupport.readCookie(request, "refreshToken").ifPresent(refreshToken -> {
            // 스프링에서 만들어놓은 쿠키 메서드 readCookie 는 반환값이 그냥 String 이 아니라 Optional String 인데(마우스 올려보면 나옴)
            // 이 Optional 은 자동 조건문이라서 if() 문 쓰고 하는 게 아니라, 뒤에 .ifPresent() 를 쓰면 true 일 경우, .ifPresent() 안의 람다가 호출되고,
            // 만약 false 라면 그냥 지나간다. 굉장히 편하다. 이걸 쿠키쓸 때 쓰라고 스프링이 만들어 놓은 것. 지금의 경우 refresh 토큰이 있으면, 뒤의 람다 실행
            log.debug("리프레시 토큰 쿠키 읽기 성공");
            try {
                // refresh 토큰이 유효하다면
                // redis 에서 삭제
                Long memberId = Long.parseLong(jwtTokenProvider.getSubject(refreshToken));  // memberId 얻어옴
                String jti = jwtTokenProvider.getJti(refreshToken);  // UUID(jti) 얻어옴
                log.debug("삭제 시도 - memberId: {}, jti: {}", memberId, jti);
                redisTokenStore.revokeRefreshToken(memberId, jti);  // refresh token 제거

            } catch (Exception e) {
                log.error("삭제 중 에러 발생: {}", e.getMessage());
                // 로그아웃 과정에서 실패가 발생할 경우, 이미 그 수단이 유효하지 않다는 뜻. 살면서 로그아웃 실패를 경험해본 적 있는가?
                // 따라서 로그아웃이 실패가 난다는 건 이미 로그인을 유지할 수 없는 상태이기 때문에 따로 예외처리를 하지 않아도 된담.
            }
        });

        /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
         2) 블랙리스트 등록 - 지금 쓰고 있는 Access Token 을 즉시 무효로 만들어서 만료되지 않았음에도 사용을 못하게 만듬.
        ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
        AccessTokenExtractor.extractBearerToken(request).ifPresent(accessToken -> {

            try {
                if (jwtTokenProvider.validateAccessToken(accessToken)) {
                    String jti = jwtTokenProvider.getJti(accessToken);
                    Instant exp = jwtTokenProvider.getExp(accessToken);
                    // 토큰의 만료 시각에서 지금 시각을 빼서 남아있는 초를 구하되, 음수가 나오면 0으로 하자.
                    long ttl = Math.max(0, exp.getEpochSecond() - Instant.now().getEpochSecond());
                    redisTokenStore.blackListAccessToken(jti, ttl);
                }
            } catch (Exception ignore) {
                // 블랙리스트에 등록하려했는데 오류가 났다?
                // 이미 오염된 토큰 > 사용 불가능한 토큰. 즉 의미없으므로 예외처리 하지 않음.
            }
        });

        /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
         3) 쿠키 제거
        ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
        refreshCookieSupport.deleteRefreshCookie(response);
        return ResponseEntity.ok(Map.of("message", "로그아웃 됨"));
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

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     react 프론트에서 코드가 전송되면, 이 코드를 이용하여 redis 에서 Access Token 찾아 반환
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    @PostMapping("/oauth2/exchange")
    public ResponseEntity<?> exchange(@RequestParam String tempCode) {

        String accessToken = redisTokenStore.exchangeCodeForToken(tempCode).orElseThrow(()-> new IllegalArgumentException("Invalied temp code"));

        return ResponseEntity.ok(Map.of("tokenType", "Bearer ", "accessToken", accessToken));
    }


    @ExceptionHandler(AuthenticationException.class)    // 원래는 따로 만들어야되는데 지금은 일단 컨트롤러에다가;;
    public String handle(AuthenticationException e) {
        log.debug("\n\n인증 실패 ㅜㅜ");
        return e.getMessage();
    }
}