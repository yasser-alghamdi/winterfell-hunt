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

at the end, a report of each execution will be generated to present the statstics of the overall findings that need additional attentions and further investigation.

```
██╗  ██╗██╗   ██╗███╗   ██╗████████╗    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
███████║██║   ██║██╔██╗ ██║   ██║       ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
██╔══██║██║   ██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
██║  ██║╚██████╔╝██║ ╚████║   ██║       ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                                                                                                                      

Winterfell hunt has completed. Completed report is loacted at DESKTOP-YASSER\Hunting\Winterfell_Hunt_Report.txt
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
in addition, complete report will be generated contains all finidings loacted in the following PATH \DESKTOP-YASSER\Hunting\Winterfell_Hunt_Report.txt
```
Winterfell hunt has completed. Completed report is loacted at DESKTOP-YASSER\Hunting\Winterfell_Hunt_Report.txt
Results statstics are the following:
```

## Demo of Execution
below is to domenstrate a demo of execution of Winterfell-Hunt as the following:

**Run Winterfell Package**
![Run_Winterfell](https://github.com/yasser-alghamdi/winterfell/blob/master/winterfell.gif?raw=true)

**Experinment Statstics**
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
below is to domenstrate a demo of execution of Winterfell-Hunt as the following:

## References

https://ericzimmerman.github.io/#!index.md

https://www.nirsoft.net/utils/
