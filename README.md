<img src="https://github.com/yasser-alghamdi/winterfell/blob/master/winterfell_logo.jpg" title="winterfell" height="15%" width="35%">

# Winterfell-Hunt
Winterfell-Hunt is a python script to perform auto threat hunting for malicious activities in windows OS based on collected data by winterfell collection package https://github.com/yasser-alghamdi/winterfell-collection.

## Winterfell-Hunt Capabilities
Winterfell-Hunt helps to reduce the size of collected data by Winterfell collection package based on performing strings/regex matching of common malciious strings, locations, techniques, etc in order to expidete the time of investigation. it covers the following functions `amcache_hunt` `shellbags_hunt` `prefetch_hunt` `security_logs_hunt` `powershell_logs_hunt` `autoruns_hunt` `schedule_tasks_hunt` `firewall_hunt` `dlls_hunt` `usnjrnl_hunt` `recycle_bin_hunt` `loki_process_hunt` `loki_file_hunt` `URL_history_hunt` `dirlisting_hunt` `iis_logs_hunt` `registry_CURRENT_USER_hunt` and `registry_LOCAL_MACHINE_hunt`

## Winterfell-Hunt Usage
Make sure to keep all scripts, and tools folder under Winterfell folder. you can run the package by execute `All-Winterfell-Scripts.bat` through administrator command prompt `cmd.exe` by nevigate to Winterfell folder. the script has the capability to identify the folder location so you can place the folder anywhere in Windows OS.

```
	██╗    ██╗██╗███╗   ██╗████████╗███████╗██████╗ ███████╗███████╗██╗     ██╗     
	██║    ██║██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝██║     ██║     
	██║ █╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██████╔╝█████╗  █████╗  ██║     ██║     
	██║███╗██║██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ██║     ██║     
	╚███╔███╔╝██║██║ ╚████║   ██║   ███████╗██║  ██║██║     ███████╗███████╗███████╗
	╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝	
	"+-------------------------------------------------------------------------+
	"| Winterfell is a windows batch script to collect windows forensics       |
	"| data and perform threat hunting for Incident Response Investigation.    |
	"| Created by yAsSeR Al-Ghamdi.                                            |
	"+-------------------------------------------------------------------------+

----------------------------------------------------
Command:
C:\Users\yasser\Desktop\winterfell-master>All-Winterfell-Scripts.bat
```

## Demo of Execution
below is to domenstrate a demo of execution of Winterfell package as the following:

**Run Winterfell Package**
![Run_Winterfell](https://github.com/yasser-alghamdi/winterfell/blob/master/winterfell.gif?raw=true)

## References

https://ericzimmerman.github.io/#!index.md

https://www.nirsoft.net/utils/
