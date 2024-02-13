_TEXT SEGMENT
EXTERN GetNtContinue: PROC

; simple APC dispatcher that does everything except dispatch APCs
KiUserApcDispatcher PROC
  _loop:
    call GetNtContinue
    mov rcx, rsp
    mov rdx, 1
    call rax
    jmp _loop
  ret
KiUserApcDispatcher ENDP

_TEXT ENDS
END