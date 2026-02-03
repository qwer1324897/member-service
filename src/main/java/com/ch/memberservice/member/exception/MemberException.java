package com.ch.memberservice.member.exception;

import lombok.Getter;

@Getter
public class MemberException extends RuntimeException{

    private final MemberErrorCode errorCode;

    public MemberException(MemberErrorCode errorCode){
        super(errorCode.getMessage()); //부모 RuntimeException의 생성자 매개변수로 에러 메시지 전달
        //부모의 생성자는 물려받지 못하므로, 부모의 생성자 호출을 통해서 전달
        this.errorCode=errorCode;
    }
}