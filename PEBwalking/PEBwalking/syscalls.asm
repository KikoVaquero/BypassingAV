extern _ssn:DWORD
extern _direccionRetornoSyscall:QWORD

.CODE
indirectSyscalling PROC
	mov r10, rcx
	mov eax, _ssn
	mov rbx, _direccionRetornoSyscall
	jmp rbx
indirectSyscalling ENDP
END