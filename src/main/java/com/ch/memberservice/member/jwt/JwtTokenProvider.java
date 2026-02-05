package com.ch.memberservice.member.jwt;

import com.ch.memberservice.member.service.MemberDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class JwtTokenProvider {

    @Value("${app.jwt.access-exp-seconds}")
    private long accessExpSeconds;

    @Value("${app.jwt.refresh-exp-seconds}")
    private long refreshExpSeconds;

    @Value("${app.jwt.secret}")
    private String secret;

    private SecretKey key;

    private final MemberDetailsService memberDetailsService;

    @PostConstruct  // JwtTokenProvider 클래스가 생성되자마자 바로 생성
    public void init() {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     토큰 발급 (로그인에 성공한 사람의 정보를 이용해야 하므로, Authentication Token이 필요
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public String createAccessToken(Authentication authentication) {

        Instant now = Instant.now();    // 현재 시간 구하기
        Instant exp = now.plusSeconds(accessExpSeconds);    // 만료 시간

        String roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        // 반복문 돌리면 빡세니, stream 객체를 이용하여 map 으로 객체안의 데이터를 문자열로 추출, "," 쉼표를 기준으로 합치기

        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .id(jti)
                .subject(authentication.getName())  // 컨트롤러에서 담은 memberId 가 들어가있음
                .claim("roles", roles)
                .claim("tokenType", "access")   // api 서버 접근 용 토큰(15분으로 설정해놓음)
                .issuedAt(Date.from(now))   // 토큰이 발급된 시간
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     Refresh Token 생성
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public String createRefreshToken(Long member_id) {

        Instant now = Instant.now();    // 현재 시간 구하기
        Instant exp = now.plusSeconds(refreshExpSeconds);    // 만료 시간

        String jti = UUID.randomUUID().toString();
        // Universally Unique Identifier. 범용 고유 식별자. 128비트 크기(32자)의 숫자로, 전 세계에서 유일성을 보장하는 고유 식별자)

        return Jwts.builder()
                .id(jti) // 고유값 (redis에 저장할 key-value 에서 key 값. 이 때 key 값은 중복가능성이 낮아야 하므로 UUID 를 사용한다.)
                .subject(String.valueOf(member_id))// OAuth2 로 로그인한 유저는 homepageId 가 null 일 수 있기 때문에 memberId 사용
                .claim("tokenType", "refresh")
                .issuedAt(Date.from(now))   // 토큰이 발급된 시간
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     Access Token 유효성 검증
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public Claims getClaims(String token) {     // 토큰 분해용 메서드
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // subject 반환 == memberId
    public String getSubject(String token) {
        return getClaims(token).getSubject();
    }

    // JTI 반환 (UUID)
    public String getJti(String token) {
        return getClaims(token).getId();
    }

    // Exp 반환 (ttl)
    public Instant getExp(String token) {
        return getClaims(token).getExpiration().toInstant();
    }

    // 검증을 원하는 토큰을 매개변수로 넘김
    public boolean validateAccessToken(String token) {

        try {
            Claims claims = getClaims(token);    // 토큰 안의 정보를 분해해서 검증해야 하기 때문에(규칙) 위에 정의한 토큰 분해용 메서드에다가 집어넣음
            return "access".equals(claims.get("tokenType", String.class)); // claims 에서 데이터 꺼낼 때는 key 값과 그 값에 대한 자료형(.class)을 명시해야 함.
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     토큰을 이용하여 Access Token 얻기
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public Authentication getAuthentication(String token) {
        // 토큰의 주인 즉, 회원의 id 꺼내기
        Claims claims = getClaims(token);
        String homepageId = claims.getSubject();    // 토큰에 넣은 아이디 꺼내기

        UserDetails userDetails = memberDetailsService.loadUserByUsername(homepageId);   // 이러면 이제 userdetails 에 있는 모든 회원정보, 비밀번호까지 싹 다 가져옴

        // 원래는 로그인 성공한 이유 최초에는 비어있던 token 에다가 유저의 모든 정보가 담긴 userDetails 를 스프링이 알아서 넣어주지만
        // 지금은 Jwt 필터를 이용한 로그인 처리를 하고 있으므로, 개발자가 직접 해주는 것.
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}