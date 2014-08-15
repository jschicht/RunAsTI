#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=Start program with same privileges as TrustedInstaller
#AutoIt3Wrapper_Res_Description=Start program with same privileges as TrustedInstaller
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#AutoIt3Wrapper_Res_File_Add=C:\tmp\RunFromToken.exe
#AutoIt3Wrapper_Res_File_Add=C:\tmp\RunFromToken64.exe
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
; Much of the code is taken from wraithdu's examples
; Modified by Joakim
#include <WinAPI.au3>
#Include <WinAPIEx.au3>
CONST $ERROR_INVALID_SID = 1337
Global Const $tagSTARTUPINFO1 = "dword cb;ptr lpReserved;ptr lpDesktop;ptr lpTitle;dword dwX;dword dwY;dword dwXSize;dword dwYSize;" & _
						"dword dwXCountChars;dword dwYCountChars;dword dwFillAttribute;dword dwFlags;ushort wShowWindow;" & _
						"ushort cbReserved2;ptr lpReserved2;ptr hStdInput;ptr hStdOutput;ptr hStdError"
Global Const $tagPROCESSINFO1 = "ptr hProcess;ptr hThread;dword dwProcessId;dword dwThreadId"
Global Const $NORMAL_PRIORITY_CLASS = 0x00000020
Global Const $CREATE_NEW_CONSOLE = 0x00000010
Global Const $CREATE_UNICODE_ENVIRONMENT = 0x00000400
Global $ghADVAPI32 = DllOpen("advapi32.dll")

If StringInStr(@OSVersion,"XP") Or StringInStr(@OSVersion,"2003") Then
	ConsoleWrite("Error: This program is meaningless in XP/2003" & @CRLF)
	Exit
EndIf

$Privs = "SeDebugPrivilege,SeAssignPrimaryTokenPrivilege,SeIncreaseQuotaPrivilege,SeImpersonateName"
$PrivsArray = StringSplit($Privs,",")
For $i = 1 To $PrivsArray[0]
	;ConsoleWrite("Now setting privilege: " & $PrivsArray[$i] & @CRLF)
	_SetPrivilege($PrivsArray[$i])
Next

If $cmdline[0] = 0 Then
	$sCmdLine = "cmd.exe"
Else
	$sCmdLine = $cmdline[1]
EndIf
$sProcessAsUser = "winlogon.exe"

$dwSessionId = DllCall("kernel32.dll", "dword", "WTSGetActiveConsoleSessionId")
If @error Or $dwSessionId[0] = 0xFFFFFFFF Then
	ConsoleWrite("WTSGetActiveConsoleSessionId: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	Exit
EndIf
$dwSessionId = $dwSessionId[0]

ConsoleWrite("Running in session: " & $dwSessionId & @CRLF)
Dim $aProcs = ProcessList($sProcessAsUser), $processPID = -1, $ret
For $i = 1 To $aProcs[0][0]
	$ret = DllCall("kernel32.dll", "int", "ProcessIdToSessionId", "dword", $aProcs[$i][1], "dword*", 0)
	If Not @error And $ret[0] And ($ret[2] = $dwSessionId) Then
		$processPID = $aProcs[$i][1]
		ExitLoop
	EndIf
Next

;ConsoleWrite("Host PID: " & $processPID & @CRLF)
If $processPID = -1 Then
	ConsoleWrite("Return 0 ; failed to get winlogon PID in current sessio")
	Exit
EndIf
Local $hProc = DllCall("kernel32.dll", "ptr", "OpenProcess", "dword", 0x001F0FFF, "int", 0, "dword", $processPID)
If @error Or Not $hProc[0] Then
	ConsoleWrite("OpenProcess: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	Exit
EndIf

$hProc = $hProc[0]
$hToken = DllCall($ghADVAPI32, "int", "OpenProcessToken", "ptr", $hProc, "dword", 0x2, "ptr*", 0)
If @error Or Not $hToken[0] Then
	ConsoleWrite("OpenProcessToken: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
	Exit
EndIf
$hToken = $hToken[3]
$hDupToken = DllCall($ghADVAPI32, "int", "DuplicateTokenEx", "ptr", $hToken, "dword", 0x1F0FFF, "ptr", 0, "int", 1, "int", 1, "ptr*", 0)
If @error Or Not $hDupToken[0] Then
	ConsoleWrite("DuplicateTokenEx: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
	DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
	Exit
EndIf

;Identify correct module
If @OSArch = "X86" Then
	$sModuleName = @TempDir&"\RunFromToken.exe"
	$TargetRCDataNumber = 1
Else
	$sModuleName = @TempDir&"\RunFromToken64.exe"
	$TargetRCDataNumber = 2
EndIf
;Get module from resource
_WriteFileFromResource($sModuleName,$TargetRCDataNumber)
If @error Or FileExists($sModuleName)=0 Then
	ConsoleWrite("Error finding module" & @CRLF)
	FileDelete($sModuleName)
	Exit
EndIf

;Set command line
$sCmdLine = $sModuleName & " trustedinstaller.exe " & $dwSessionId & " " & $sCmdLine

;Start service
run("cmd.exe /c sc start trustedinstaller", "", @SW_HIDE, 0x10000)

$hDupToken = $hDupToken[6]
$pEnvBlock = _GetEnvironmentBlock($sProcessAsUser, $dwSessionId) ; target process
$dwCreationFlags = BitOR($NORMAL_PRIORITY_CLASS, $CREATE_NEW_CONSOLE)
If $pEnvBlock Then $dwCreationFlags = BitOR($dwCreationFlags, $CREATE_UNICODE_ENVIRONMENT)
$SI = DllStructCreate($tagSTARTUPINFO1)
DllStructSetData($SI, "cb", DllStructGetSize($SI))
$PI = DllStructCreate($tagPROCESSINFO1)
$sDesktop = "winsta0\default"
$lpDesktop = DllStructCreate("wchar[" & StringLen($sDesktop) + 1 & "]")
DllStructSetData($lpDesktop, 1, $sDesktop)
DllStructSetData($SI, "lpDesktop", DllStructGetPtr($lpDesktop))
$ret = DllCall($ghADVAPI32, "bool", "CreateProcessWithTokenW", "handle", $hDupToken, "dword", 0, "ptr", 0, "wstr", $sCmdLine, "dword", $dwCreationFlags, "ptr", $pEnvBlock, "wstr", @WindowsDir, "ptr", DllStructGetPtr($SI), "ptr", DllStructGetPtr($PI))
If @error or Not $ret[0] Then
	ConsoleWrite("Error in CreateProcessWithTokenW: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	$ret = DllCall($ghADVAPI32, "int", "CreateProcessAsUserW", "handle", $hDupToken, "ptr", 0, "wstr", $sCmdLine, "ptr", 0, "ptr", 0, "int", 0, "dword", $dwCreationFlags, "ptr", $pEnvBlock, "ptr", 0, "ptr", DllStructGetPtr($SI), "ptr", DllStructGetPtr($PI))
	If Not @error And $ret[0] Then
		ConsoleWrite("Success CreateProcessAsUserW created new process: " & DllStructGetData($PI, "dwProcessId") & @CRLF)
		DllCall("kernel32.dll", "int", "CloseHandle", "ptr", DllStructGetData($PI, "hThread"))
		DllCall("kernel32.dll", "int", "CloseHandle", "ptr", DllStructGetData($PI, "hProcess"))
	Else
		ConsoleWrite("Error in CreateProcessAsUserW: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	EndIf
Else
	ConsoleWrite("Success CreateProcessWithTokenW created new process: " & DllStructGetData($PI, "dwProcessId") & @CRLF)
EndIf

If $pEnvBlock Then DllCall("userenv.dll", "int", "DestroyEnvironmentBlock", "ptr", $pEnvBlock)
DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hDupToken)
DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hProc)
FileDelete($sModuleName)
Exit

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
	Local $hProc = DllCall("kernel32.dll", "ptr", "OpenProcess", "dword", 0x02000000, "int", 0, "dword", $processPID)
	If @error Or Not $hProc[0] Then Return 0
	$hProc = $hProc[0]
	; open process token
	$hToken = DllCall($ghADVAPI32, "int", "OpenProcessToken", "ptr", $hProc, "dword", $dwAccess, "ptr*", 0)
	If @error Or Not $hToken[0] Then
		ConsoleWrite("OpenProcessToken: " & _WinAPI_GetLastErrorMessage() & @CRLF)
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
    Local $TOKEN_ADJUST_PRIVILEGES = 0x20
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
		ConsoleWrite("AdjustTokenPrivileges for "&$Privilege&": " & _WinAPI_GetLastErrorMessage() & @CRLF)
		If $lasterror = 1300 Then
			$RightsAdder = _LsaAddAccountRights(@UserName, $Privilege)
			If not @error then
				ConsoleWrite("Reboot required for changes to take effect" & @CRLF)
			Else
				ConsoleWrite("Warning: The right was probably not added correctly to your account" & @CRLF)
				Return SetError(1,0,0)
			EndIf
		EndIf
	EndIf
    DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
    Return ($call[0] <> 0) ; $call[0] <> 0 is success
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
;	ConsoleWrite("LsaAddAccountRights Dec " & _LsaNtStatusToWinError($iResult[0]) & @CRLF)
	ConsoleWrite("LsaAddAccountRights 0x" & Hex(_LsaNtStatusToWinError($iResult[0]),8) & @CRLF)
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

Func NT_SUCCESS($status)
    If 0 <= $status And $status <= 0x7FFFFFFF Then
        Return True
    Else
        Return False
    EndIf
EndFunc

Func _WriteFileFromResource($OutPutName,$RCDataNumber)
	If FileExists($OutPutName) Then FileDelete($OutPutName)
	If Not FileExists($OutPutName) Then
		Local $hResource = _WinAPI_FindResource(0, 10, '#'&$RCDataNumber)
		If @error Or $hResource = 0 Then
			ConsoleWrite("Error: Resource not found" & @CRLF)
			Return SetError(1, 0, 0)
		EndIf
		Local $iSize = _WinAPI_SizeOfResource(0, $hResource)
		If @error Or $iSize = 0 Then
			ConsoleWrite("Error: Resource size not retrieved" & @CRLF)
			Return SetError(1, 0, 0)
		EndIf
		Local $hData = _WinAPI_LoadResource(0, $hResource)
		If @error Or $hData = 0 Then
			ConsoleWrite("Error: Resource could not be loaded" & @CRLF)
			Return SetError(1, 0, 0)
		EndIf
		Local $pData = _WinAPI_LockResource($hData)
		If @error Or $pData = 0 Then
			ConsoleWrite("Error: Resource not locked" & @CRLF)
			Return SetError(1, 0, 0)
		EndIf
		Local $tBuffer=DllStructCreate('align 1;byte STUB['&$iSize&']', $pData)
		Local $DriverData = DllStructGetData($tBuffer,'STUB')
		If @error or $DriverData = "" Then
			ConsoleWrite("Error: Could not put driver data into buffer" & @CRLF)
			Return SetError(1, 0, 0)
		EndIf
		Local $hFile = FileOpen($OutPutName,2)
		If Not FileWrite($hFile,$DriverData) Then
			ConsoleWrite("Error: Could not write driver file" & @CRLF)
			Return SetError(1, 0, 0)
		EndIf
		FileClose($hFile)
		Return 1
	Else
		Return 1
	EndIf
EndFunc