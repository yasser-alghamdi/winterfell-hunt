<img src="https://github.com/yasser-alghamdi/winterfell/blob/master/winterfell_logo.jpg" title="winterfell" height="15%" width="35%">

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

at the end, a report of each execution will be generated to present the statstics of the overall findings that need additional attentions and further investigation.

```
██╗  ██╗██╗   ██╗███╗   ██╗████████╗    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
███████║██║   ██║██╔██╗ ██║   ██║       ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
██╔══██║██║   ██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
██║  ██║╚██████╔╝██║ ╚████║   ██║       ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                                                                                                                      

Winterfell hunt has completed. Results statstics are the following:
------------------------------------
Total Findings Count:
600
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
0
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

**Experinment Statstics

below table to show the reducing size statistics as the following:
Parser 		         | Befor           | After
-----------------   | -------------  | --------------
BrowserHistory      | 
Srum                | [Saleh Muhaysin](https://github.com/salehmuhaysin/SRUM_parser)
CSV                 | Custom by Saleh Muhaysin
Recyclebin          | Custom by Muteb Alqahtani
Scheduled Tasks     | Custom by Muteb Alqahtani
Prefetch            | [MBromiley](https://github.com/bromiley/tools/tree/master/win10_prefetch)
Windows Events      | [dgunter](https://github.com/dgunter/evtxtoelk)
Amcache	            | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
bits_admin          | [ANSSI](https://github.com/ANSSI-FR/bits_parser)
Jumplist            | [Bhupendra Singh](https://github.com/Bhupipal/JumpListParser)
MFT                 | [dkovar](https://github.com/dkovar/analyzeMFT)
RUA                 | [davidpany](https://github.com/davidpany/WMI_Forensics)
Shellbags           | [Willi Ballenthin](https://github.com/williballenthin/shellbags)
Shimcache           | [MANDIANT](https://github.com/mandiant/ShimCacheParser)
Shortcuts           | [HarmJ0y](https://github.com/HarmJ0y/pylnker)
UsnJrnl             | [PoorBillionaire](https://github.com/PoorBillionaire/USN-Journal-Parser)
WMI_Persistence     | [davidpany](https://github.com/davidpany/WMI_Forensics)
ComputerName        | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
DHCP                | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
InstalledApp        | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
InstalledComponents | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
LastVisitedMRU      | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
LaunchTracing       | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
OpenSaveMRU         | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
ProfileList         | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
ShellExtensions     | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
TimeZoneInformation | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
TypedUrls           | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
Uninstall           | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
UserAssist          | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
WordWheelQuery      | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
Bam                 | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
AppCompatFlags      | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
MuiCache            | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
RunMRU              | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
Sysinternals        | [Muteb Alqahtani](https://github.com/muteb/RegSkewer)
TerminalServerClient| [Muteb Alqahtani](https://github.com/muteb/RegSkewer)

**Examples of Detected Malicious Activities

below is to domenstrate a demo of execution of Winterfell-Hunt as the following:

## References

https://ericzimmerman.github.io/#!index.md

https://www.nirsoft.net/utils/
