RunAsTI or RunAsTrustedInstaller

Is a tool to launch a program of choice (usually cmd.exe) with the same privileges as the TrustedInstaller. That privilege is very powerfull! Actually the tool makes a clone of the token from TrustedInstaller, and thus the newly created process has an identical token.

Why would you need it? Sometimes it is just not enough to just be running as "nt authority\system". Maybe it's a file or a registry key that is locked. Running a tool with this powerfull privilege most likely solve that. Usually such an issue may be due to Windows Resource Protection (WRP) protecting it (previously called Windows File Protection (WFP)); http://msdn.microsoft.com/en-us/library/windows/desktop/aa382503(v=vs.85).aspx

How do you run it? Simply double click it and cmd.exe will launch. Or pass it the program to launch as parameter.

There are reports that the tool does not work over an RDP session.

The tool is actually a merge of 2 previous tools; RunAsSystem and RunFromToken. The curious ones might notice that RunFromToken is attached as a resource.

Have added the original source of RunFromToken as the exe's must be present in current directory when building RunAsTi.

The tool only runs on nt6.x (Vista and later), since TrustedInstaller does not exist on earlier Windows versions.

Requirement: Administrator.