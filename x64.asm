;
;	Windows 10 PE+ STUB
;

bits 64 

%define ROUND(x,y) (((x+(y-1))/y)*y)
%define RVA(x) (x - IMAGE_TEXT_SECTION) / 0x200*0x1000+0x1000
%define RVA(x,y) RVA(y)+(x-y)

IMAGE_BSS_SIZE equ 8

IMAGE_SIZE equ RVA(IMAGE_END) + ROUND(IMAGE_BSS_SIZE, 0x1000)

;
;	IMAGE_DOS_HEADER
;
	dw 0x5a4d
	dw 0x0080
	dw 0x0001
	dw 0
	dw 0x0004
	dw 0x0010
	dw 0xffff
	dw 0
	dw 0x0140
	dw 0
	dw 0
	dw 0
	dw 0x0040
	dw 0
	times 4 dw 0
	dw 0
	dw 0
	times 10 dw 0
	dd IMAGE_NT_SIGNATURE

	db 0x0e,0x1f,0xba,0x0e,0x00,0xb4,0x09,0xcd,0x21,0xb8,0x01,0x4c,0xcd,0x21,0x54,0x68
	db 0x69,0x73,0x20,0x70,0x72,0x6f,0x67,0x72,0x61,0x6d,0x20,0x63,0x61,0x6e,0x6e,0x6f
	db 0x74,0x20,0x62,0x65,0x20,0x72,0x75,0x6e,0x20,0x69,0x6e,0x20,0x44,0x4f,0x53,0x20
	db 0x6d,0x6f,0x64,0x65,0x2e,0x0d,0x0a,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	
	align 8, db 0
	
;
;	IMAGE_NT_SIGNATURE
;
IMAGE_NT_SIGNATURE:
	dd 0x00004550
	
;
;	IMAGE_FILE_HEADER
;
	dw 0x8664
	dw 4 ; sections
	dd 0xbad1dea5
	dd 0
	dd 0
	dw IMAGE_OPTIONAL_HEADER64_SIZE
	dw 0x002f
	
;
;	IMAGE_OPTIONAL_HEADER64
;
IMAGE_OPTIONAL_HEADER64:
	dw 0x20b
	db 14
	db 0
	dd ROUND(IMAGE_TEXT_SIZE, 0x200)
	dd ROUND(IMAGE_DATA_SIZE, 0x200)
	dd ROUND(IMAGE_BSS_SIZE, 0x200)
	dd RVA(ENTRY_POINT) ;ENTRY_POINT
	dd RVA(IMAGE_TEXT_SECTION) ;IMAGE_TEXT_SECTION
	dq 0x40000000
	dd 0x1000
	dd 0x200
	dw 6
	dw 0
	dw 0
	dw 0
	dw 6
	dw 0
	dd 0
	dd IMAGE_SIZE ;0x5000 ;0x4000
	dd ROUND(SIZEOFHEADER, 0x200)
	dd 0
	dw 2
	dw 0
	dq 0x100000
	dq 0x1000
	dq 0x100000
	dq 0x1000
	dd 0
	dd 0x00000010

;
;	IMAGE_DATA_DIRECTORY
;
	dd 0, 0									; Export
	dd RVA(IMAGE_IDATA_SECTION, IMAGE_IDATA_SECTION), IMAGE_IDATA_SIZE				; Import
	dd 0, 0									; Resource
	dd 0, 0									; Exception
	dd 0, 0									; Certificate
	dd 0, 0									; Base relocation
	dd 0, 0									; Debug
	dd 0, 0									; Architecture
	dd 0, 0									; Global Ptr
	dd 0, 0									; Tls
	dd 0, 0									; Load config
	dd 0, 0									; Bound import
	dd 0, 0									; Import address
	dd 0, 0									; Delay import
	dd 0, 0									; Clr
	dd 0, 0									; Reserved
	
IMAGE_OPTIONAL_HEADER64_SIZE equ $ - IMAGE_OPTIONAL_HEADER64

;
;	IMAGE_SECTION_HEADER
;
IMAGE_SECTION_HEADER:
	dq ".text"
	dd ROUND(IMAGE_TEXT_SIZE, 0x1000)
	dd RVA(IMAGE_TEXT_SECTION)
	dd ROUND(IMAGE_TEXT_SIZE, 0x200)
	dd IMAGE_TEXT_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x00000020 | 0x60000000
	
	dq ".data"
	dd ROUND(IMAGE_DATA_SIZE, 0x1000)
	dd RVA(IMAGE_DATA_SECTION)
	dd ROUND(IMAGE_DATA_SIZE, 0x200)
	dd IMAGE_DATA_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x80000000 | 0x40000000 | 0x00000040
	
	dq ".idata"
	dd ROUND(IMAGE_IDATA_SIZE, 0x1000)
	dd RVA(IMAGE_IDATA_SECTION)
	dd ROUND(IMAGE_IDATA_SIZE, 0x200)
	dd IMAGE_IDATA_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x80000000 | 0x40000000 | 0x00000040
	
	dq ".bss"
	dd IMAGE_BSS_SIZE
	dd 0x4000
	dd 0
	dd IMAGE_BSS_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x80000000 | 0x40000000 | 0x00000080
	
	SIZEOFHEADER equ $ - $$ + 4
	
	align 0x200, db 0

;
;	.text
;
IMAGE_TEXT_SECTION:
	ENTRY_POINT:
	sub rsp, 8*5
	mov r9d, 0
	lea r8, [RVA(_caption, IMAGE_DATA_SECTION) + 0x40000000]
	lea rdx, [RVA(_message, IMAGE_DATA_SECTION) + 0x40000000]
	mov rcx, 0
	call [RVA(MessageBoxA, IMAGE_IDATA_SECTION) + 0x40000000]
	
	mov ecx, eax
	call [RVA(ExitProcess, IMAGE_IDATA_SECTION) + 0x40000000]
IMAGE_TEXT_SIZE equ $ - IMAGE_TEXT_SECTION

	align 0x200, db 0

;
;	.data
;
IMAGE_DATA_SECTION:
	_caption: db 'PE64',0
	_message: db 'Gwildor',0
IMAGE_DATA_SIZE equ $ - IMAGE_DATA_SECTION

	align 0x200, db 0
	
;
;	.idata
;
IMAGE_IDATA_SECTION:

	dd 0,0,0, RVA(kernel_name, IMAGE_IDATA_SECTION), RVA(KERNEL32, IMAGE_IDATA_SECTION)
	dd 0,0,0, RVA(user_name, IMAGE_IDATA_SECTION), RVA(USER32, IMAGE_IDATA_SECTION)
	dd 0,0,0,0,0

	KERNEL32:
		ExitProcess: dq RVA(_ExitProcess, IMAGE_IDATA_SECTION)
		dq 0
	USER32:
		MessageBoxA: dq RVA(_MessageBoxA, IMAGE_IDATA_SECTION)
		dq 0

	kernel_name: db 'KERNEL32.DLL', 0
	user_name: db 'USER32.DLL', 0

	_ExitProcess: dw 0
		db 'ExitProcess', 0
	_MessageBoxA: dw 0
		db 'MessageBoxA', 0
			
	align 0x02, db 0
	
IMAGE_IDATA_SIZE equ $ - IMAGE_IDATA_SECTION

	align 0x200, db 0

IMAGE_BSS_SECTION:
IMAGE_END:
