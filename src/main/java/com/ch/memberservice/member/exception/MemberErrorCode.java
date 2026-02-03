package com.ch.memberservice.member.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum MemberErrorCode {
    MEMBER_NOT_FOUND("회원 정보를 찾을 수 없습니다", HttpStatus.NOT_FOUND),
    MEMBER_CREATE_FAIL("회원 등록에 실패", HttpStatus.INTERNAL_SERVER_ERROR),
    MEMBER_UPDATE_FAIL("회원 수정에 실패", HttpStatus.INTERNAL_SERVER_ERROR),
    MEMBER_DELETE_FAIL("회원 삭제에 실패", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String message;
    private final HttpStatus status;

    MemberErrorCode(String message, HttpStatus status){
        this.message=message;
        this.status=status;
    }
    public String getCode(){
        return this.name();
    }
}