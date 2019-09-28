#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=C:\Program Files (x86)\AutoIt3\Icons\au3.ico
#AutoIt3Wrapper_Outfile=RunFromToken32.exe
#AutoIt3Wrapper_Outfile_x64=RunFromToken64.exe
#AutoIt3Wrapper_Compile_Both=y
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=Start a program based on the privileges from a given process' token
#AutoIt3Wrapper_Res_Description=Start a program based on the privileges from a given process' token
#AutoIt3Wrapper_Res_Fileversion=1.0.0.3
#AutoIt3Wrapper_Res_ProductVersion=1.0.0.3
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#AutoIt3Wrapper_AU3Check_Parameters=-w 3 -w 5
#AutoIt3Wrapper_Run_Au3Stripper=y
#Au3Stripper_Parameters=/sf /sv /rm /pe
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

#include <WinAPI.au3>
#include <String.au3>

Global $ghADVAPI32 = DllOpen("advapi32.dll")
CONST $ERROR_INVALID_SID = 1337
Global Const $tagOBJECTATTRIBUTES = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
$tagSTARTUPINFO1 = "dword cb;ptr lpReserved;ptr lpDesktop;ptr lpTitle;dword dwX;dword dwY;dword dwXSize;dword dwYSize;" & _
						"dword dwXCountChars;dword dwYCountChars;dword dwFillAttribute;dword dwFlags;ushort wShowWindow;" & _
						"ushort cbReserved2;ptr lpReserved2;ptr hStdInput;ptr hStdOutput;ptr hStdError"
$tagPROCESSINFO1 = "ptr hProcess;ptr hThread;dword dwProcessId;dword dwThreadId"

If $cmdline[0] <> 3 Then
	ConsoleWrite("RunFromToken: Wrong number of args supplied: " & $cmdline[0] & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Try: RunFromToken.exe param1 param2 param3" & @CRLF)
	ConsoleWrite("param1 is target process name" & @CRLF)
	ConsoleWrite("param2 is session ID to start new process in" & @CRLF)
	ConsoleWrite("param3 is the command line to execute" & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Example:" & @CRLF)
	ConsoleWrite("RunFromToken.exe trustedinstaller.exe 1 regedit" & @CRLF)
	ConsoleWrite("(do not forget the extension in param1)" & @CRLF)
	Exit
EndIf
$Privs = "SeDebugPrivilege,SeAssignPrimaryTokenPrivilege,SeIncreaseQuotaPrivilege"
$PrivsArray = StringSplit($Privs,",")
For $i = 1 To $PrivsArray[0]
	ConsoleWrite("RunFromToken: Now setting privilege: " & $PrivsArray[$i] & @CRLF)
	_SetPrivilege($PrivsArray[$i])
Next
Global $sProcessAsUser = $cmdline[1]
Global $TargetSessionId = $cmdline[2]
Global $sCmdLine = $cmdline[3]
;$TargetSessionId = Dec($TargetSessionId)
$TargetSessionId = Int($TargetSessionId)
ConsoleWrite("RunFromToken: TargetSessionId=" & $TargetSessionId & @CRLF)

; create app command line
Local $aProcs = ProcessList($sProcessAsUser), $processPID = -1, $ret
For $i = 1 To $aProcs[0][0]
	$ret = DllCall("kernel32.dll", "int", "ProcessIdToSessionId", "dword", $aProcs[$i][1], "dword*", 0)
	If Not @error And $ret[0]  Then
		$processPID = $aProcs[$i][1]
		ExitLoop
	EndIf
Next
ConsoleWrite("RunFromToken: Host PID: " & $processPID & @CRLF)
If $processPID = -1 Then
	ConsoleWrite("RunFromToken: Process ID not found, are you sure the process is running?")
	Exit
EndIf

Local $hProc = _NtOpenProcess($processPID)
If @error Then
	ConsoleWrite("RunFromToken: Ntstatus: 0x" & Hex($hProc,8) & @CRLF)
	Exit
Else
	$hProc = $hProc
EndIf
; open process token
$hToken = DllCall($ghADVAPI32, "int", "OpenProcessToken", "ptr", $hProc, "dword", 0x000F01FF, "ptr*", 0)
If @error Or Not $hToken[0] Then
	ConsoleWrite("RunFromToken: OpenProcessToken: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
	Exit
EndIf
$hToken = $hToken[3]
; duplicate token
Local $hDupToken = DllCall($ghADVAPI32, "int", "DuplicateTokenEx", "ptr", $hToken, "dword", 0x1F0FFF, "ptr", 0, "int", 1, "int", 1, "ptr*", 0)
If @error Or Not $hDupToken[0] Then
	ConsoleWrite("RunFromToken: DuplicateTokenEx: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
	Exit
EndIf
$hDupToken = $hDupToken[6]
; Set the session to start new process in
$myStruct = DllStructCreate("byte[4]")
DllStructSetData($myStruct,1,$TargetSessionId)
_SetTokenInformation($hDupToken, $TOKENSESSIONID, DllStructGetPtr($myStruct), DllStructGetSize($myStruct))
If @error then Exit
; get environment block
Local $pEnvBlock
$pEnvBlock = _GetEnvironmentBlock($sProcessAsUser, $TargetSessionId)
; create new process in user's session, with user's environment block
Local $dwCreationFlags = BitOR($NORMAL_PRIORITY_CLASS, $CREATE_NEW_CONSOLE)
If $pEnvBlock Then $dwCreationFlags = BitOR($dwCreationFlags, $CREATE_UNICODE_ENVIRONMENT)
Local $SI = DllStructCreate($tagSTARTUPINFO1)
DllStructSetData($SI, "cb", DllStructGetSize($SI))
Local $PI = DllStructCreate($tagPROCESSINFO1)
Local $sDesktop = "winsta0\default"
Local $lpDesktop = DllStructCreate("wchar[" & StringLen($sDesktop) + 1 & "]")
DllStructSetData($lpDesktop, 1, $sDesktop)
DllStructSetData($SI, "lpDesktop", DllStructGetPtr($lpDesktop))

_WinAPI_SetLastError(0)
$ret = DllCall($ghADVAPI32, "int", "CreateProcessAsUserW",  "ptr", $hDupToken,  "ptr", 0,  "wstr", $sCmdLine,  "ptr", 0,  "ptr", 0,  "int", 0,  "dword", $dwCreationFlags,  "ptr", $pEnvBlock,  "ptr", 0,  "ptr", DllStructGetPtr($SI),  "ptr", DllStructGetPtr($PI))
ConsoleWrite("RunFromToken: CreateProcessAsUserW=" & $ret[0] & "  error=" & @error & " LastError=" & _WinAPI_GetLastError() & @CRLF)

If Not @error And $ret[0] Then
	ConsoleWrite("RunFromToken: New process created successfully: " & DllStructGetData($PI, "dwProcessId") & @CRLF)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", DllStructGetData($PI, "hThread"))
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", DllStructGetData($PI, "hProcess"))
Else
	ConsoleWrite("RunFromToken: CreateProcessAsUserW: " & _WinAPI_GetLastErrorMessage() & @CRLF)
EndIf
If $pEnvBlock Then  DllCall("userenv.dll", "int", "DestroyEnvironmentBlock", "ptr", $pEnvBlock)
DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hDupToken)
DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
;Local $iAnswer = MsgBox(BitOR($MB_YESNO, $MB_SYSTEMMODAL), "RunFromToken", "Exit")



Func _GetEnvironmentBlock($sProcess, $dwSession)
	Local Const $MAXIMUM_ALLOWED1 = 0x02000000
	Local Const $dwAccess = BitOR(0x2, 0x8) ; TOKEN_DUPLICATE | TOKEN_QUERY

	; get PID of process in current session
	Local $aProcs = ProcessList($sProcess), $processPID = -1, $ret = 0
	For $i = 1 To $aProcs[0][0]
		$ret = DllCall("kernel32.dll", "int", "ProcessIdToSessionId", "dword", $aProcs[$i][1], "dword*", 0)
		If Not @error And $ret[0] And ($ret[2] = $dwSession) Then
			$processPID = $aProcs[$i][1]
			ExitLoop
		EndIf
	Next
	If $processPID = -1 Then Return 0 ; failed to get PID
	; open process
	Local $hProc = DllCall("kernel32.dll", "ptr", "OpenProcess", "dword", $MAXIMUM_ALLOWED1, "int", 0, "dword", $processPID)
	If @error Or Not $hProc[0] Then Return 0
	$hProc = $hProc[0]
	; open process token
	$hToken = DllCall($ghADVAPI32, "int", "OpenProcessToken", "ptr", $hProc, "dword", $dwAccess, "ptr*", 0)
	If @error Or Not $hToken[0] Then
		DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
		Return 0
	EndIf
	$hToken = $hToken[3]
	; create a new environment block
	Local $pEnvBlock = DllCall("userenv.dll", "int", "CreateEnvironmentBlock", "ptr*", 0, "ptr", $hToken, "int", 1)
	If Not @error And $pEnvBlock[0] Then $ret = $pEnvBlock[1]
	; close handles
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
	Return $ret
EndFunc

Func _SetPrivilege($Privilege)
    Local $tagLUIDANDATTRIB = "int64 Luid;dword Attributes"
    Local $count = 1
    Local $tagTOKENPRIVILEGES = "dword PrivilegeCount;byte LUIDandATTRIB[" & $count * 12 & "]" ; count of LUID structs * sizeof LUID struct
;    Local $TOKEN_ADJUST_PRIVILEGES = 0x20
    Local $SE_PRIVILEGE_ENABLED = 0x2

    Local $curProc = DllCall("kernel32.dll", "ptr", "GetCurrentProcess")
	Local $call = DllCall("advapi32.dll", "int", "OpenProcessToken", "ptr", $curProc[0], "dword", $TOKEN_ALL_ACCESS, "ptr*", "")
    If Not $call[0] Then Return False
    Local $hToken = $call[3]

    $call = DllCall("advapi32.dll", "int", "LookupPrivilegeValue", "str", "", "str", $Privilege, "int64*", "")
    Local $iLuid = $call[3]

    Local $TP = DllStructCreate($tagTOKENPRIVILEGES)
	Local $TPout = DllStructCreate($tagTOKENPRIVILEGES)
    Local $LUID = DllStructCreate($tagLUIDANDATTRIB, DllStructGetPtr($TP, "LUIDandATTRIB"))

    DllStructSetData($TP, "PrivilegeCount", $count)
    DllStructSetData($LUID, "Luid", $iLuid)
    DllStructSetData($LUID, "Attributes", $SE_PRIVILEGE_ENABLED)

    $call = DllCall("advapi32.dll", "int", "AdjustTokenPrivileges", "ptr", $hToken, "int", 0, "ptr", DllStructGetPtr($TP), "dword", DllStructGetSize($TPout), "ptr", DllStructGetPtr($TPout), "dword*", 0)
	$lasterror = _WinAPI_GetLastError()
	If $lasterror <> 0 Then
		ConsoleWrite("RunFromToken: AdjustTokenPrivileges ("&$Privilege&"): " & _WinAPI_GetLastErrorMessage() & @CRLF)
		If $lasterror = 1300 Then
			_LsaAddAccountRights(@UserName, $Privilege)
			If not @error then
				ConsoleWrite("RunFromToken: Reboot required for changes to take effect" & @CRLF)
			Else
				ConsoleWrite("RunFromToken: Error: The right was probably not added correctly to your account" & @CRLF)
				Return SetError(1,0,0)
			EndIf
		EndIf
	EndIf
    DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
    Return ($call[0] <> 0) ; $call[0] <> 0 is success
EndFunc

Func _SetTokenInformation($hToken, $iTokenInformation, $vTokenInformation, $iTokenInformationLength)
	Local $aCall = DllCall("advapi32.dll", "bool", "SetTokenInformation", "handle", $hToken, "int", $iTokenInformation, "struct*", $vTokenInformation, "dword", $iTokenInformationLength)
	If @error Or Not $aCall[0] Then
		ConsoleWrite("RunFromToken: SetTokenInformation: " & _WinAPI_GetLastErrorMessage() & @CRLF)
		Return SetError(1, @extended, False)
	EndIf
	Return True
EndFunc

Func _NtOpenProcess($PID)
    Local $sOA = DllStructCreate($tagOBJECTATTRIBUTES)
    DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", 0)
    DllStructSetData($sOA, "ObjectName", 0)
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)

    Local $ClientID = DllStructCreate("dword_ptr UniqueProcessId;dword_ptr UniqueThreadId")
    DllStructSetData($ClientID, "UniqueProcessId", $PID)
    DllStructSetData($ClientID, "UniqueThreadId", 0)

    Local $aCall = DllCall("ntdll.dll", "hwnd", "NtOpenProcess", "handle*", 0, "dword", 0x001F0FFF, "struct*", $sOA, "struct*", $ClientID)
    If Not NT_SUCCESS($aCall[0]) Then
        ConsoleWrite("RunFromToken: Error in NtOpenProcess: " & Hex($aCall[0], 8) & @CRLF)
        Return SetError(1, 0, $aCall[0])
    Else
        Return $aCall[1]
    EndIf
EndFunc

Func NT_SUCCESS($status)
    If 0 <= $status And $status <= 0x7FFFFFFF Then
        Return True
    Else
        Return False
    EndIf
EndFunc

Func _LsaAddAccountRights($sName, $sRight)
	Local $hPolicy, $tSid, $pSid, $iLength, $iSysError
	Local $tUnicode, $pUnicode, $iResult, $tRight, $pRight
	$tSid = _LookupAccountName($sName)
	$pSid = DllStructGetPtr($tSid)
	If Not _IsValidSid($pSid) Then Return SetError(@error, 0, 0)
	$hPolicy = _LsaOpenPolicy(0x811)
	$iLength = StringLen($sRight) * 2
	$tRight = DllStructCreate("wchar[" & $iLength & "]")
	$pRight = DllStructGetPtr($tRight)
	DllStructSetData($tRight, 1, $sRight)
	$tUnicode = DllStructCreate("ushort Length;ushort MemSize;ptr wBuffer")
	$pUnicode = DllStructGetPtr($tUnicode)
	DllStructSetData($tUnicode, "Length", $iLength)
	DllStructSetData($tUnicode, "MemSize", $iLength + 2)
	DllStructSetData($tUnicode, "wBuffer", $pRight)
	$iResult = DllCall("advapi32.dll", "dword", "LsaAddAccountRights", _
					"hWnd", $hPolicy, "ptr", $pSid, _
					"ptr", $pUnicode, "ulong", 1)
;	ConsoleWrite("RunFromToken: LsaAddAccountRights Dec " & _LsaNtStatusToWinError($iResult[0]) & @CRLF)
	ConsoleWrite("RunFromToken: LsaAddAccountRights 0x" & Hex(_LsaNtStatusToWinError($iResult[0]),8) & @CRLF)
	$tSid = 0
	_LsaClose($hPolicy)
	$iSysError = _LsaNtStatusToWinError($iResult[0])
	Return SetError($iSysError, 0, $iSysError = 0)
EndFunc

Func _LsaOpenPolicy($iAccess)
	Local $hPolicy, $tLsaAttr, $pLsaAttr
	$tLsaAttr = DllStructCreate("ulong;hWnd;ptr;ulong;ptr[2]")
	$pLsaAttr = DllStructGetPtr($tLsaAttr)
	$hPolicy = DllCall("advapi32.dll", "ulong", "LsaOpenPolicy", _
					"ptr", 0, "ptr", $pLsaAttr, "int", $iAccess, "hWnd*", 0)
	Return SetError(_LsaNtStatusToWinError($hPolicy[0]), 0, $hPolicy[4])
EndFunc

Func _LsaClose($hPolicy)
        Local $iResult
        $iResult = DllCall("advapi32.dll", "ulong", "LsaClose", "hWnd", $hPolicy)
        Return SetError(_LsaNtStatusToWinError($iResult[0]), 0, $iResult[0] = 0)
EndFunc

Func _LookupAccountName($sName, $sSystem = "")
        Local $iResult, $tSid, $pSid, $tDomain, $pDomain
        $iResult = DllCall("advapi32.dll", "int", "LookupAccountName", _
                        "str", $sSystem, "str", $sName, _
                        "ptr", 0, "int*", 0, "ptr", 0, "int*", 0, "int*", 0)
        If $iResult[4] = 0 Then Return SetError($ERROR_INVALID_SID, 0, 0)
        $tSid = DllStructCreate("ubyte[" & $iResult[4] & "]")
        $tDomain = DllStructCreate("ubyte[" & $iResult[6] & "]")
        $pSid = DllStructGetPtr($tSid)
        $pDomain = DllStructGetPtr($tDomain)
        $iResult = DllCall("advapi32.dll", "int", "LookupAccountName", _
                        "str", $sSystem ,"str", $sName, _
                        "ptr", $pSid, "int*", $iResult[4], _
                        "ptr", $pDomain, "int*", $iResult[6], "int*", 0)
        Return SetError(Not $iResult[0], $iResult[7], $tSid)
EndFunc

Func _IsValidSid($pSid)
        Local $iResult
        $iResult = DllCall("advapi32.dll", "int", "IsValidSid", "ptr", $pSid)
        If $iResult[0] Then Return SetError(0, 0, True)
        Return SetError($ERROR_INVALID_SID, 0, 0)
EndFunc

Func _LsaNtStatusToWinError($iNtStatus)
	Local $iSysError
	$iSysError = DllCall("Advapi32.dll", "ulong", "LsaNtStatusToWinError", "dword", $iNtStatus)
	Return $iSysError[0]
EndFunc