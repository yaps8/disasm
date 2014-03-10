section .text
global _start

_start:

; db 0x31, 0xdb, 0x90, 0x90, 0xb8
; db 0x66, 0x0f, 0x1f, 0x84, 0xb8, 0x00, 0x00, 0x00, 0x00
mov	ebx, 1

back:
call printEax
call printEbx
call printEcx
call printNL
; jmp exit
cmp	ebx, 0
jne	A

B:
sub     edi, 2
db	0xb8            ; mov eax,xxxx

A:
xor ecx, ecx
inc ecx
inc ecx

cmp	ecx, 2
je	suite	

junk:
nop
nop
;db 0x0a
;db 0x05

suite:
cmp ecx, 2
je	b4HEP

MEP:
db 0x66, 0x0f, 0x1f, 0x84
HEP:
db 0x31, 0xdb, 0x90, 0x90, 0xba
db 0x66, 0x0f, 0x1f, 0x84, 0x2d, 0x31, 0xc9, 0x41, 0x41
jmp	fin

b4HEP:
mov	ebx, HEP
jmp	ebx

fin:
call printEax
call printNL
cmp	eax, 0x0
jne	back

exit:
mov ebx, 0
mov eax, 1
int 0x80

printEax:
mov esi, eax
push eax
push ebx
push ecx
push edx
add esi, 0x30
push 0x00
push 0x0a
push esi
mov	eax, 0x04 ; write
mov ebx, 0x01 ; stdout (?)
mov ecx, esp ; message
mov edx, 12  ; size
int 80h
add esp, 12
pop edx
pop ecx
pop ebx
pop eax
ret

printEbx:
mov esi, ebx
push eax
push ebx
push ecx
push edx
add esi, 0x30
push 0x00
push 0x0a
push esi
mov	eax, 0x04 ; write
mov ebx, 0x01 ; stdout (?)
mov ecx, esp ; message
mov edx, 12  ; size
int 80h
add esp, 12
pop edx
pop ecx
pop ebx
pop eax
ret

printEcx:
mov esi, ecx
push eax
push ebx
push ecx
push edx
add esi, 0x30
push 0x00
push 0x0a
push esi
mov	eax, 0x04 ; write
mov ebx, 0x01 ; stdout (?)
mov ecx, esp ; message
mov edx, 12  ; size
int 80h
add esp, 12
pop edx
pop ecx
pop ebx
pop eax
ret

printNL:
push eax
push ebx
push ecx
push edx
push 0x00
push 0x0a
mov	eax, 0x04 ; write
mov ebx, 0x01 ; stdout (?)
mov ecx, esp ; message
mov edx, 8  ; size
int 80h
add esp, 8
pop edx
pop ecx
pop ebx
pop eax
ret
