;
;	Windows 10 PE+ STUB
;

bits 64 

%define ALIGN(x, y) (((x+(y-1))/y)*y)
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
	dw 3
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
	dd ALIGN(IMAGE_TEXT_SECTION_SIZE, 0x200)
	dd 0
	dd 0
	dd 0x1000 ;ENTRY_POINT
	dd 0x1000 ;IMAGE_TEXT_SECTION
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
	dd 0x4000
	dd ALIGN(SIZEOFHEADER, 0x200)
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
	dd 0x3000, IMAGE_IDATA_SECTION_SIZE		; Import
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
SIZEOFHEADER equ $ - $$

;
;	IMAGE_SECTION_HEADER
;
IMAGE_SECTION_HEADER:
	dq ".text"
	dd IMAGE_TEXT_SECTION_SIZE
	dd 0x1000
	dd ALIGN(1, 0x200)
	dd IMAGE_TEXT_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x00000020 | 0x60000000
	
	dq ".data"
	dd IMAGE_DATA_SECTION_SIZE
	dd 0x2000
	dd ALIGN(1, 0x200)
	dd IMAGE_DATA_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x80000000 | 0x40000000 | 0x00000040
	
	dq ".idata"
	dd IMAGE_IDATA_SECTION_SIZE
	dd 0x3000
	dd ALIGN(1, 0x200)
	dd IMAGE_IDATA_SECTION
	dd 0
	dd 0
	dw 0
	dw 0
	dd 0x80000000 | 0x40000000 | 0x00000040
	
	align 0x200, db 0

;
;	.text
;
IMAGE_TEXT_SECTION:
	ENTRY_POINT:
	sub	rsp,8*5
	mov	r9d,0
	lea	r8,[_caption - 0x400 + 0x2000 + 0x40000000]
	lea	rdx,[_message - 0x400 + 0x2000 + 0x40000000]
	mov	rcx,0
	call [MessageBoxA - 0x600 + 0x3000 + 0x40000000]

	mov	ecx,eax
	call [ExitProcess - 0x600 + 0x3000 + 0x40000000]
IMAGE_TEXT_SECTION_SIZE equ $ - IMAGE_TEXT_SECTION

	align 0x200, db 0

;
;	.data
;
IMAGE_DATA_SECTION:
	_caption: db 'PE64',0
	_message: db 'Hello World!',0
IMAGE_DATA_SECTION_SIZE equ $ - IMAGE_DATA_SECTION

	align 0x200, db 0
	
;
;	.idata
;
IMAGE_IDATA_SECTION:

	dd 0,0,0, kernel_name + 0x2A00, kernel_table + 0x2A00
	dd 0,0,0, user_name + 0x2A00, user_table + 0x2A00
	dd 0,0,0,0,0

	kernel_table:
		ExitProcess: dq _ExitProcess + 0x2A00
		dq 0
	user_table:
		MessageBoxA: dq _MessageBoxA + 0x2A00
		dq 0

	kernel_name: db 'KERNEL32.DLL',0
	user_name: db 'USER32.DLL',0

	_ExitProcess: dw 0
		db 'ExitProcess',0
	_MessageBoxA: dw 0
		db 'MessageBoxA',0
			
	align 0x02, db 0
	
IMAGE_IDATA_SECTION_SIZE equ $ - IMAGE_IDATA_SECTION

	align 0x200, db 0
	
IMAGE_SIZE equ $ - $$


