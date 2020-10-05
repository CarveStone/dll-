;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Win32汇编实现DLL的远程注入
; by CarveStone
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; dll注入.asm
; 32位或64位dll 注入
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 使用 nmake 或下列命令进行编译和链接:
; ml /c /coff dll注入.asm
; rc dll注入.rc
; Link /subsystem:windows dll注入.obj dll注入.res
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.386
		.model flat, stdcall
		option casemap :none
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Include 文件定义
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
; Equ 等值定义
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
ICO_MAIN	equ		1000h	;图标
DLG_MAIN	equ		1
IDC_DLLPATH	equ		2
IDC_CHOOSEPATH	equ		3
IDC_INPUTPID	equ		4
IDC_INJECTION	equ		5
IDC_UNLOADING	equ		6

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 数据段
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.data?

hInstance	dd		?
pid		dd		?	;输入的pid
szModule	dd		?	;注入的dll
lpDllName	dd		?
szMyDllFull	db		MAX_PATH dup(?)
lpLoadLibrary	dd		?
hProcess	dd		?

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 数据段
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.data 

 szGetModuleHandleA	db	'GetModuleHandleA',0
 ;szLoadLibraryA		db	'LoadLibraryA',0
 szFreeLibrary		db	'FreeLibrary',0
 szErr1			db	'进程打开错误',0
 szErr2			db	'虚拟分配错误',0
 szErr3			db	'写入进程内存错误',0
 szErr4			db	'获取进程地址错误',0
 szErr5			db	'创建远程线程错误',0
 szFailed		db	'注入失败!',0
 szSuccessfully		db	'注入成功!',0
 ;szDllKernel	db	'Kernel32.dll',0
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 常量
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.const
szDllFileExt	db	'dll(*.dll);exe(*.exe);所有文件',0,0
szLoadLibrary	db	'LoadLibraryA',0
szDllKernel	db	'Kernel32.dll',0
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 代码段
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
				;	dll注入
				invoke	GetDlgItemInt,hWnd,IDC_INPUTPID,NULL,FALSE
				invoke	RemoteInjectModule,eax,addr szMyDllFull

				;*********************************************************************
			.elseif	ax == IDC_UNLOADING

			.elseif	ax == IDC_CHOOSEPATH
				;*********************************************************************
				;	读取dll文件路径
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
