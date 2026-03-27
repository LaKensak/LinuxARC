;
;   vmcall.asm - VMCALL wrapper with Ophion signature
;   Passes the signature in R10/R11/R12 so the hypervisor accepts the call
;
;   UINT64 asm_vmcall(UINT64 rcx_num, UINT64 rdx_p1, UINT64 r8_p2, UINT64 r9_p3);
;
;   Windows x64 calling convention:
;       RCX = vmcall_num (already in place)
;       RDX = param1 (already in place)
;       R8  = param2 (already in place)
;       R9  = param3 (already in place)
;

.CODE

asm_vmcall PROC
    ; Save non-volatile registers we'll use
    push    r10
    push    r11
    push    r12

    ; Load Ophion signature into R10/R11/R12
    mov     r10, 048564653h             ; 'HVFS'
    mov     r11, 0564d43414c4ch         ; 'VMCALL'
    mov     r12, 04e4f485950455256h     ; 'NOHYPERV'

    ; RCX/RDX/R8/R9 are already set by the caller (Windows x64 ABI)
    vmcall

    ; RAX now contains the result from the hypervisor

    ; Restore non-volatile registers
    pop     r12
    pop     r11
    pop     r10
    ret
asm_vmcall ENDP

END
