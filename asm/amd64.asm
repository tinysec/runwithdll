;Project: LdrInject amd64
;Author: root@tinysec.net
;File:	main.asm of LdrInject amd64

option casemap:none



	
.code
;---------------------------------------------------------------------------
EntryPoint proc
	nop

	push rbp
	mov rbp , rsp
	and rsp , 0FFFFFFF0h
	sub rsp , 200h
	
	pushfq
	
	; pushaq
	push    rax		
    push    rcx		
    push    rdx		
    push    rbx		
    push    rsi		
    push    rdi		
    push    r8		
    push    r9		
    push    r10		
    push    r11		
    push    r12		
    push    r13		
    push    r14		
    push    r15		
	
	push rsi
	push rdi
	push rcx
	
	jmp _restore_hook_prepare
	
_restore_hook_start:
	mov rdi , 1111111111111111h	; LdrLoadDll
	mov rcx , 5
	rep movsb
	
	pop rcx
	pop rdi
	pop rsi
	
_sign_event:

	lea rdx , [rbp - 20h]	; PreviousState
	mov QWORD PTR  [rdx] , 0

	mov rcx , 4444444444444444h	; hLoadEvent
	mov rax , 5555555555555555h
	
	sub rsp , 108h
		call rax		; NtSetEvent
	add rsp , 108h
	
_load_my_dll:

	lea r9 , [rbp - 20h]	;	pModuleHandle 
	mov QWORD PTR [r9] , 0

	mov r8 , 2222222222222222h	; pusDllFile
	xor rdx , rdx		; nFlags
	xor rcx , rcx		; pszSearchPath
	mov rax , 1111111111111111h	; LdrLoadDll
	
	sub rsp , 108h
		call rax
	add rsp , 108h

_direct_ret:
	
	; popaq
	pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    
    popfq
	
	add rsp , 200h
	mov rsp , rbp
	pop rbp
	
	; jump to origin
	db 0FFh , 25h , 00h , 00h , 00h , 00h
	db 11h , 11h , 11h , 11h ,  11h ,  11h ,  11h ,  11h	; LdrLoadDll
	
_restore_hook_prepare:
	call _get_savebytes_addr
_get_savebytes_addr:
	pop rsi
	add rsi , 0Ah
	jmp _restore_hook_start
	
	; saved bytes
	db 33h , 33h , 33h , 33h ,  33h ,  33h ,  33h ,  33h
	nop


EntryPoint endp
		
		
;---------------------------------------------------------------------------
end
