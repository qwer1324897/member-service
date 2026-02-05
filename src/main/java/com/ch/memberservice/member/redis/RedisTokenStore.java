package com.ch.memberservice.member.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class RedisTokenStore {
    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     Redis 키 설계 (key - value) // SET name "Jin" << 이거
     rt:{member_id} : {jti}   // refresh 토큰 생성할 때 UUID 로 만든 고유값(변수명: jti) 사용.  실제 key값 예시) rt:17:asldgkj-asgdlkasjdg-asgdlkhasdl
     rt 는 refresh token jti 는 jwt id
     위에가 key 값이고, value 값을 정해야 하는데, 이 때 value 값은 보안상 실제 값이 아닌 가상 해시값으로 넣는다.
     rt:current(접속 상태를 의미):{member_id}  // 추가로 접속 상태를 확인할 수 있게 current 를 넣는다. 실제 예시) rt:current UUID
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/

    private final StringRedisTemplate redisTemplate;    // CRUD 전담 객체

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     Refresh Token 저장
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void saveRefreshToken(Long memberId, String jti, String refreshToken, long ttl) {
        // Refresh Token 을 Redis 에 그냥 원문으로 넣으면 보안상 위험하므로 암호화 시켜서 넣기
        String hashedToken = sha256(refreshToken);

        // rt:{member_id} : {jti} 형식의 Refresh Token 저장.
        redisTemplate.opsForValue().set("rt:" + memberId + ":" + jti, hashedToken, Duration.ofSeconds(ttl));  // key, value, ttl 순으로 넣기

        // rt:current:{member_id} 형식의 refresh token 현재 상태 정보 저장
        redisTemplate.opsForValue().set("rt:current:" + memberId, jti, Duration.ofSeconds(ttl));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     Refresh Token 조회 (현재 유효한 refresh 토큰 조회)
     Refresh Token 의 존재를 조회하려면 먼저 rt:current:(memberId) 를 통해 현재 사용되고 있는 JTI 를 가져와서
     이 JTI 를 갖는 토큰을 찾아야 한다. 없으면 로그인, 로그아웃 한 적이 없거나 폐기 등 유효하지 않은 상태로 간주.
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public String getCurrentRefreshJti(Long memberId) {
        return redisTemplate.opsForValue().get("rt:current:" + memberId);   // UUID의 jti 가 반환
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     유효한 Refresh Token 의 존재 여부 판단
     이 메서드는 사용자가 Refresh Token 을 지참하여 서버로 전송했을 때 호출될 메서드
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public boolean matchesRefreshToken(Long memberId, String jti, String refreshToken) {
        String currentJti = getCurrentRefreshJti(memberId);

        // 현재 상태를 표현하는 상태값이 존재하지 않거나, 일치하는 토큰의 jti 가 없을 경우
        if(currentJti == null || !currentJti.equals(jti)) return false;

        // 서버에 저장된 refresh token 을 가져오기
        String savedHash = redisTemplate.opsForValue().get("rt:" + memberId + ":" + jti);
        if(savedHash == null) return false;

        return savedHash.equals(sha256(refreshToken));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     Refresh Token 폐기(회전(= rotation = 재발급), 로그아웃)
     DEL rt:{memberId}:{jti}
     DEL rt:current:{memberId}
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public void revokeRefreshToken(Long memberId, String jti) {  // revoke = 철회하다
        redisTemplate.delete("rt:" + memberId + ":" + jti);  // refresh token 삭제
        redisTemplate.delete("rt:current:" + memberId);  // refresh token 의 상태값도 삭제
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     전부 폐기(강제 로그아웃)
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public void revokeAllByUser(Long memberId) {

        String jti = getCurrentRefreshJti(memberId);

        if(jti != null) {
            revokeRefreshToken(memberId, jti);
        } else {
            redisTemplate.delete("rt:current:" + memberId);
        }
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     블랙리스트 등록 (Access Token. Refresh Token 아님)
     SET bl:at:{jti} 1 EX 200
     bl 은 black list, at 는 access token
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public void blackListAccessToken(String accessJti, long ttl) {
        if(ttl <= 0) return;
        redisTemplate.opsForValue().set("bl:at:" + accessJti, "1", Duration.ofSeconds(ttl));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     블랙리스트 확인
     SET bl:at:{jti} 1 EX 200
     1 은 있다의 의미로 사용. 1대신에 뭐 O 라던지 있을 유 써도 됨
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public boolean isAccessTokenBlacklisted(String accessJti) {
        Boolean exist = redisTemplate.hasKey("bl:at:" + accessJti);

        return (exist!=null) && exist;
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     임시코드 저장 (저장 값으로 Access Token 이용, 보안을 위해 1분간 유지)
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public void saveTempCode(String tempCode, String accessToken, long ttl) {
        redisTemplate.opsForValue().set("oauth2:code:" + tempCode, accessToken, Duration.ofSeconds(ttl));
    }

    /*ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
     임시코드를 이용한 Access Token 반환
    ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ*/
    public Optional<String> exchangeCodeForToken(String tempCode) {
        String accessToken = redisTemplate.opsForValue().get("oauth2:code:" + tempCode);

        if(accessToken==null) return Optional.empty();  // 토큰 유효성 검사
        redisTemplate.delete("oauth2:code:" + tempCode);    // 토큰 반환 시 즉시 삭제
        return Optional.of(accessToken);
    }

}