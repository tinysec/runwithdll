;Project: LdrInject i386
;Author: root@tinysec.net
;File:	main.asm of LdrInject i386

.686
.xmm
.mmx
.model flat,stdcall
option casemap:none

.code
;---------------------------------------------------------------------------
EntryPoint proc
	nop
	
	push ebp
	mov ebp , esp
	and esp , 0FFFFFFF0h
	sub esp , 200h
	
	pushfd
	pushad
	
	push esi
	push edi
	push ecx
	
	jmp _restore_hook_prepare
	
_restore_hook_start:
	mov edi , 11111111h	; LdrLoadDll
	mov ecx , 5
	rep movsb
	
	pop ecx
	pop edi
	pop esi
	
	
_sign_event:
	
	lea eax , [ebp - 20h]
	mov DWORD PTR  [eax] , 0
	push eax		; PreviousState
	
	push 44444444h	; hLoadEvent
	mov eax , 55555555h
	call eax		; NtSetEvent
	
_load_my_dll:

	lea eax , [ebp - 20h]	
	mov DWORD PTR [eax] , 0
	push eax	;	pModuleHandle 
	
	push 22222222h	; pusDllFile
	push 0			; nFlags
	push 0			; pszSearchPath
	mov eax , 11111111h	; LdrLoadDll
	call eax
	
_direct_ret:
	popad
	popfd
	
	add esp , 200h
	mov esp , ebp
	pop ebp
	
	; jump to origin
	push 11111111h	; LdrLoadDll
	ret 
	
_restore_hook_prepare:
	call _get_savebytes_addr
_get_savebytes_addr:
	pop esi
	add esi , 6
	jmp _restore_hook_start
	
	; saved bytes
	db 33h , 33h , 33h , 33h
	nop

EntryPoint endp
		
		
;---------------------------------------------------------------------------
end EntryPoint
