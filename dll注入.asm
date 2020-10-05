;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Win32���ʵ��DLL��Զ��ע��
; by CarveStone
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; dllע��.asm
; 32λ��64λdll ע��
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; ʹ�� nmake ������������б��������:
; ml /c /coff dllע��.asm
; rc dllע��.rc
; Link /subsystem:windows dllע��.obj dllע��.res
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.386
		.model flat, stdcall
		option casemap :none
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Include �ļ�����
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
include		windows.inc
include		user32.inc
includelib	user32.lib
include		kernel32.inc
includelib	kernel32.lib
include		comdlg32.inc
includelib	comdlg32.lib

RemoteInjectModule    PROTO :DWORD,:DWORD
;RemoteUnloadModule    PROTO :DWORD,:DWORD
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Equ ��ֵ����
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
ICO_MAIN	equ		1000h	;ͼ��
DLG_MAIN	equ		1
IDC_DLLPATH	equ		2
IDC_CHOOSEPATH	equ		3
IDC_INPUTPID	equ		4
IDC_INJECTION	equ		5
IDC_UNLOADING	equ		6

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; ���ݶ�
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.data?

hInstance	dd		?
pid		dd		?	;�����pid
szModule	dd		?	;ע���dll
lpDllName	dd		?
szMyDllFull	db		MAX_PATH dup(?)
lpLoadLibrary	dd		?
hProcess	dd		?

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; ���ݶ�
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.data 

 szGetModuleHandleA	db	'GetModuleHandleA',0
 ;szLoadLibraryA		db	'LoadLibraryA',0
 szFreeLibrary		db	'FreeLibrary',0
 szErr1			db	'���̴򿪴���',0
 szErr2			db	'����������',0
 szErr3			db	'д������ڴ����',0
 szErr4			db	'��ȡ���̵�ַ����',0
 szErr5			db	'����Զ���̴߳���',0
 szFailed		db	'ע��ʧ��!',0
 szSuccessfully		db	'ע��ɹ�!',0
 ;szDllKernel	db	'Kernel32.dll',0
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; ����
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.const
szDllFileExt	db	'dll(*.dll);exe(*.exe);�����ļ�',0,0
szLoadLibrary	db	'LoadLibraryA',0
szDllKernel	db	'Kernel32.dll',0
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; �����
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.code
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
RemoteInjectModule	proc	dwProcID,pszModule
	;local	hProcess

	invoke	GetModuleHandle,addr szDllKernel
	invoke	GetProcAddress,eax,offset szLoadLibrary
	mov	lpLoadLibrary,eax

	invoke	OpenProcess,PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or \
			PROCESS_VM_WRITE,FALSE,dwProcID
	.if	eax
		mov	hProcess,eax
		invoke	VirtualAllocEx,hProcess,NULL,MAX_PATH,MEM_COMMIT,PAGE_READWRITE
		.if	eax
			mov	lpDllName,eax
			invoke	WriteProcessMemory,hProcess,eax,pszModule,MAX_PATH,NULL
			invoke	CreateRemoteThread,hProcess,NULL,0,lpLoadLibrary,lpDllName,0,NULL
			invoke	CloseHandle,eax
		.else
			invoke	MessageBox,NULL,addr szErr2,NULL,MB_OK
		.endif
		invoke	CloseHandle,hProcess
	.else
		invoke	MessageBox,NULL,addr szFailed,NULL,MB_OK
	.endif
	mov	eax,1
	ret
RemoteInjectModule	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_ProcDlgMain	proc	uses ebx edi esi hWnd,wMsg,wParam,lParam
		local	@szBuffer[MAX_PATH]:byte
		local	@stOpenFileName:OPENFILENAME

		mov	eax,wMsg
		.if	eax == WM_CLOSE
			invoke	EndDialog,hWnd,NULL
		.elseif	eax == WM_INITDIALOG
			invoke	LoadIcon,hInstance,ICO_MAIN
			invoke	SendMessage,hWnd,WM_SETICON,ICON_BIG,eax
		.elseif	eax == WM_COMMAND
			mov	eax,wParam
			.if	ax == IDC_INJECTION
				;*********************************************************************
				;	dllע��
				invoke	GetDlgItemInt,hWnd,IDC_INPUTPID,NULL,FALSE
				invoke	RemoteInjectModule,eax,addr szMyDllFull

				;*********************************************************************
			.elseif	ax == IDC_UNLOADING

			.elseif	ax == IDC_CHOOSEPATH
				;*********************************************************************
				;	��ȡdll�ļ�·��
				invoke	RtlZeroMemory,addr @stOpenFileName,sizeof OPENFILENAME
				invoke	RtlZeroMemory,addr @szBuffer,sizeof @szBuffer
				mov	@stOpenFileName.lStructSize,SIZEOF @stOpenFileName
				mov	@stOpenFileName.Flags,OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST
				push	hWnd
				pop	@stOpenFileName.hwndOwner
				mov	@stOpenFileName.lpstrFilter,offset szDllFileExt
				lea	eax,@szBuffer
				mov	@stOpenFileName.lpstrFile,eax
				mov	@stOpenFileName.nMaxFile,MAX_PATH
				invoke	GetOpenFileName,addr @stOpenFileName
				invoke	SetDlgItemText,hWnd,IDC_DLLPATH,addr @szBuffer
				lea	eax,@szBuffer
				mov	szModule,eax
				;invoke	GetCurrentDirectory,MAX_PATH,addr szMyDllFull
				invoke	lstrcat,addr szMyDllFull,addr @szBuffer
				
				;**********************************************************************
			.endif
		.else
			mov	eax,FALSE
			ret
		.endif
		mov	eax,TRUE
		ret

_ProcDlgMain	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
start:
		invoke	GetModuleHandle,NULL
		mov	hInstance,eax
		invoke	DialogBoxParam,hInstance,DLG_MAIN,NULL,offset _ProcDlgMain,NULL
		invoke	ExitProcess,NULL
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		end	start
