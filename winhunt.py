#!/usr/bin/python
#coding=CP437

import os
import sys
import re
from colored import fg, bg, attr

banner =("""

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
""")


# clear up the report content & add banner
cname = str(sys.argv[1])
res_path = os.getcwd() + "\\" + cname
os.chdir(res_path + '\\')
try:
    os.mkdir('Hunting')
    os.chdir('Hunting' + '\\')
except:
    pass
print(banner)
write_hunt_path = ("Hunting")
os.chdir(res_path + '\\' + write_hunt_path)
if os.path.exists("Winterfell_Hunt_Report.txt"):
   os.remove("Winterfell_Hunt_Report.txt")
else:
   pass
with open("Winterfell_Hunt_Report.txt", "a") as intro:
    intro.write(banner.decode('CP437') + '\n')

# hunt inside amcache file
def amcache_hunt():
    print('\n' + '%s[+] Hunting in Amcache File%s' % (fg(117), attr(0)))
    amch_hunt_path = ("Forensics\\Amcache\\AppCompat")
    os.chdir(res_path + '\\' + amch_hunt_path) 
    cmd = 'type *.tsv > amcache.txt'
    os.system(cmd)
    final = []
    with open("amcache.txt", "r") as amch_sch:
        for line in amch_sch:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)|(.+).bat\b(.+)|(.+)\\[$0-9$].exe(.+)|(.+)\\[$a-z$].exe(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as amch_sch_res:
                    amch_sch_res.write("[+] Hunting in Amcache File:" + '\n' + (line))
                    amch_sch_res.write('\n')
    print("%s[+] Finished Hunting in Amcache File%s" % (fg(118), attr(0)))


# hunt inside shellbags file
def bags_hunt():
    print('\n' + '%s[+] Hunting in Shellbags File%s' % (fg(117), attr(0)))
    bags_hunt_path = ("Forensics\\Shellbags")
    os.chdir(res_path + '\\' + bags_hunt_path) 
    cmd = 'type *.tsv > shellbags.txt'
    os.system(cmd)
    final = []
    with open("shellbags.txt", "r") as bags_sch:
        for line in bags_sch:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)|(.+).bat\b(.+)|(.+).vbs\b(.+)|(.+).ps1\b(.+)|(.+).zip\b(.+)|(.+).aspx\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as bags_sch_res:
                    bags_sch_res.write("[+] Hunting in Shellbags File:" + '\n' + (line))
                    bags_sch_res.write('\n')
    print("%s[+] Finished Hunting in Shellbags File%s" % (fg(118), attr(0)))

# hunt inside powershell logs
def powershell_logs_hunt():
    print('\n' + '%s[+] Hunting in Powershell Logs Files%s' % (fg(117), attr(0)))
    pshell_hunt_path = ("Logs\\Evtlogs\\Hunting\\Powershell")
    os.chdir(res_path + '\\' + pshell_hunt_path)
    match = []
    final = [] 
    with open("powershell.txt", "r") as pshell_sch:
        for line in pshell_sch:
            if re.match('(.+)Host Application =(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+)Credential(.+)|(.+)PowerView(.+)|(.+)PowerUp(.+)|(.+)Exploit-(.+)|(.+)Invoke-(.+)|(.+)DownloadString(.+)|(.+)WebClient(.+)|(.+)DownloadData(.+)|(.+)FromBase64String(.+)|(.+)ConvertTo-Base36(.+)|(.+)GzipStream(.+)|(.+)Invoke-Encode(.+)|(.+)Hidden(.+)|(.+)DownloadFile(.+)|(.+)UploadFile(.+)|(.+)UseShellExecute(.+)|(.+)Shell.Application(.+)|(.+)Stop-Process(.+)|(.+)enc(.+)|(.+)enco(.+)|(.+)nop(.+)|(.+)Chr(.+)|(.+)Invoke-MainWorker(.+)|(.+)JAB(.+)|(.+)TVqQAAMA(.+)|(.+)PAA(.+)|(.+)encodedCommand(.+)|(.+)SQBFAF(.+)|(.+)aWV4(.+)|(.+)aQBIA(.+)|(.+)R2V0(.+)|(.+)UploadData(.+)|(.+)dmFy(.+)|(.+)dgBhA(.+)|(.+)UploadString(.+)|(.+)SUVY(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as pshell_sch_res:
                    pshell_sch_res.write("[+] Hunting in Powershell Logs Files:" + '\n' + (line))
                    pshell_sch_res.write('\n')
    print("%s[+] Finished Hunting in Powershell Logs Files%s" % (fg(118), attr(0)))

# hunt inside firewall rules
def firewall_hunt():
    print('\n' + '%s[+] Hunting in Firewall Rules%s' % (fg(117), attr(0)))
    fw_hunt_path = ("Network\\FWconfig")
    os.chdir(res_path + '\\' + fw_hunt_path)
    cmd = 'type fwconfig.txt > fwconfig_decoded.txt'
    os.system(cmd)
    match = []
    final = []
    with open("fwconfig_decoded.txt", "r") as fw_sch:
        for line in fw_sch:
            if re.match(r'(.+)ogram\b(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+)Temp\b(.+)|(.+)ogramData\b(.+)|(.+)blic\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as fw_sch_res:
                    fw_sch_res.write("[+] Hunting in Firewall Rules:" + '\n' + (line))
                    fw_sch_res.write('\n')
    print("%s[+] Finished Hunting in Firewall Rules%s" % (fg(118), attr(0)))

# hunt inside dll file
def dll_hunt():
    print('\n' + '%s[+] Hunting in Dlls File%s' % (fg(117), attr(0)))
    dll_hunt_path = ("System\\Dlls")
    os.chdir(res_path + '\\' + dll_hunt_path)
    match = []
    final = []
    with open("dlls.txt", "r") as dll_sch:
        for line in dll_sch:
            if re.match('(.+)0000(.+)', line):
                match.append(line)
        for line in match:
            if not re.match(r'(.+)\\SYSTEM32\b(.+)|(.+)\\system32\b(.+)|(.+)\\System32\b(.+)|(.+)\\WinSxS\b(.+)|(.+)\\Program Files\b(.+)|(.+)\\SysWOW64\b(.+)|(.+)\\sysWOW64\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as dll_sch_res:
                    dll_sch_res.write("[+] Hunting in Dlls File:" + '\n' + (line))
                    dll_sch_res.write('\n')
    print("%s[+] Finished Hunting in Dlls File%s" % (fg(118), attr(0)))

# hunt inside recycle bin
def recycle_bin_hunt():
    print('\n' + '%s[+] Hunting in Recycle Bin%s' % (fg(117), attr(0)))
    recy_hunt_path = ("Forensics\\Recycle")
    os.chdir(res_path + '\\' + recy_hunt_path)
    match = []
    final = []
    with open("recycle1-RBCmd.txt", "r") as recy_sch:
        for line in recy_sch:
            if re.match('(.+)line:(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as recy_sch_res:
                    recy_sch_res.write("[+] Hunting in Recycle Bin:" + '\n' + (line))
                    recy_sch_res.write('\n')
    print("%s[+] Finished Hunting in Recycle Bin%s" % (fg(118), attr(0)))

# hunt inside prefetch data
def prefetch_hunt():
    print('\n' + '%s[+] Hunting in Prefetch Data%s' % (fg(117), attr(0)))
    prfch_hunt_path = ("Forensics\\Prefetch")
    os.chdir(res_path + '\\' + prfch_hunt_path)
    cmd = 'type htmlprefetch.html > htmlprefetch_decoded.txt'
    os.system(cmd)
    final = []
    with open("htmlprefetch_decoded.txt", 'rb') as prfch_sch:
        for line in prfch_sch:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as prfch_sch_res:
                    prfch_sch_res.write("[+] Hunting in Prefetch Data:" + '\n' + (line))
                    prfch_sch_res.write('\n')
    print("%s[+] Finished Hunting in Prefetch Data%s" % (fg(118), attr(0)))


# hunt inside current user registry
def registry_CURRENT_USER_hunt():
    print('\n' + '%s[+] Hunting in CURRENT_USER Registry%s' % (fg(117), attr(0)))
    curn_reg_hunt_path = ("Registry\\Registry")
    os.chdir(res_path + '\\' + curn_reg_hunt_path)
    cmd = 'type reginfo-HKEY_CURRENT_USER.txt > reginfo-HKEY_CURRENT_USER_decoded.txt'
    os.system(cmd)
    match = []
    final = []
    with open("reginfo-HKEY_CURRENT_USER_decoded.txt", 'rb') as curn_reg_sch:
        for line in curn_reg_sch:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+).bat\b(.+)|(.+).vbs\b(.+)|(.+).ps1\b(.+)|(.+).exe\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as curn_reg_sch_res:
                    curn_reg_sch_res.write("[+] Hunting in CURRENT_USER Registry:" + '\n' + (line))
                    curn_reg_sch_res.write('\n')
    print("%s[+] Finished Hunting in CURRENT_USER Registry%s" % (fg(118), attr(0)))

# hunt inside local machine registry
def registry_LOCAL_MACHINE_hunt():
    print('\n' + '%s[+] Hunting in LOCAL_MACHINE Registry%s' % (fg(117), attr(0)))
    local_reg_hunt_path = ("Registry\\Registry")
    os.chdir(res_path + '\\' + local_reg_hunt_path)
    cmd = 'type reginfo-HKEY_LOCAL_MACHINE.txt > reginfo-HKEY_LOCAL_MACHINE_decoded.txt'
    os.system(cmd)
    match = []
    final = []
    with open("reginfo-HKEY_LOCAL_MACHINE_decoded.txt", 'rb') as local_reg_sch:
        for line in local_reg_sch:
             if re.match(r'(.+)\\Image File Execution Options\b(.+)|(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+).bat\b(.+)|(.+).vbs\b(.+)|(.+).ps1\b(.+)|(.+).exe\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as local_reg_sch_res:
                    local_reg_sch_res.write("[+] Hunting in LOCAL_MACHINE Registry:" + '\n' + (line))
                    local_reg_sch_res.write('\n')
    print("%s[+] Finished Hunting in LOCAL_MACHINE Registry%s" % (fg(118), attr(0)))

# hunt inside security logs
def security_logs_hunt():
    print('\n' + '%s[+] Hunting in Security Logs Files%s' % (fg(117), attr(0)))
    sec_hunt_path = ("Logs\\Evtlogs\\Hunting\\Security")
    os.chdir(res_path + '\\' + sec_hunt_path) 
    match = []
    final = []
    with open("security.txt", "rb") as sec_sch:
        for line in sec_sch:
            if re.match('(.+)New Process Name:(.+)', line):
                match.append(line)
        for line in match:
             if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as sec_sch_res:
                    sec_sch_res.write("[+] Hunting in Security Logs:" + '\n' + (line))
                    sec_sch_res.write('\n')
    print("%s[+] Finished Huntsing in Security Logs Files%s" % (fg(118), attr(0)))
     
# hunt inside autoruns file
def autoruns_hunt():
    print('\n' + '%s[+] Hunting in Autoruns File%s' % (fg(117), attr(0)))
    auto_hunt_path = ("Presistance\\Autoruns")
    os.chdir(res_path + '\\' + auto_hunt_path) 
    cmd = 'type autoruns.txt > autoruns_decoded.txt'
    os.system(cmd)
    final = []
    with open("autoruns_decoded.txt", "r") as auto_sch:
        for line in auto_sch:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)|(.+).bat\b(.+)|(.+).vbs\b(.+)|(.+).ps1\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as auto_sch_res:
                    auto_sch_res.write("[+] Hunting in Autoruns File:" + '\n' + (line))
                    auto_sch_res.write('\n')
    print("%s[+] Finished Hunting in Autoruns File%s" % (fg(118), attr(0)))

# hunt inside schedule tasks
def schedule_tasks_hunt():
    print('\n' + '%s[+] Hunting in Schedule Tasks%s' % (fg(117), attr(0)))
    tasksch_hunt_path = ("Presistance\\Schtask")
    os.chdir(res_path + '\\' + tasksch_hunt_path) 
    final = []
    with open("schtasks.txt", "rb") as task_sch:
        for line in task_sch:
            if re.match(r'(.+)\\Temp\b(.+)|(.+)\\ProgramData\b(.+)|(.+)\\Public\b(.+)|(.+).bat\b(.+)|(.+).vbs\b(.+)|(.+).ps1\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as task_sch_res:
                    #print("Found:" + '\n'.join(final))
                    task_sch_res.write("[+] Hunting in Schedule Tasks:" + '\n' + (line))
                    task_sch_res.write('\n')
    print("%s[+] Finished Hunting in Schedule Tasks%s" % (fg(118), attr(0)))

# hunt inside usnjrnl file
def usnjrnl_hunt():
    print('\n' + '%s[+] Hunting in UsnJrnl File%s' % (fg(117), attr(0)))
    usnj_hunt_path = ("Forensics\\UsnJrnl")
    os.chdir(res_path + '\\' + usnj_hunt_path) 
    match = []
    final = []
    with open("usnjrnl.txt", "r") as usnj_sch:
        for line in usnj_sch:
            if re.match('(.+)FileName =(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+).bat\b(.+)|(.+).vbs\b(.+)|(.+).ps1\b(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as usnj_sch_res:
                    usnj_sch_res.write("[+] Hunting in UsnJrnl File:" + '\n' + (line))
                    usnj_sch_res.write('\n')
    print("%s[+] Finished Hunting in UsnJrnl File%s" % (fg(118), attr(0)))

# hunt inside loki processscan module
def loki_proc_hunt():
    print('\n' + '%s[+] Hunting in Loki ProcessScan Module%s' % (fg(117), attr(0)))
    loki_proc_hunt_path = ("Malware\\Loki-Check")
    os.chdir(res_path + '\\' + loki_proc_hunt_path) 
    match = []
    final = []
    with open("loki-results.log", "rb") as loki_proc_sch:
        for line in loki_proc_sch:
            if re.match('(.+)ProcessScan(.+)', line):
                match.append(line)
        for line in match:
            if re.match(r'(.+)DownloadString(.+)|(.+)WebClient(.+)|(.+)DownloadData(.+)|(.+)FromBase64String(.+)|(.+)ConvertTo-Base36(.+)|(.+)GzipStream(.+)|(.+)Invoke-Encode(.+)|(.+)UseShellExecute(.+)|(.+)Hidden(.+)|(.+)Stop-Process(.+)|(.+)enc(.+)|(.+)Chr(.+)|(.+)Invoke-MainWorker(.+)|(.+)encodedCommand(.+)|(.+)UploadData(.+)|(.+)bat(.+)|(.+)vbs(.+)|(.+)ps1(.+)|(.+)UploadString(.+)|(.+)SUVY(.+)|(.+)wscript(.+)|(.+)cscript(.+)|(.+)SHADOWCOPY DELETE(.+)|(.+)process call create(.+)|(.+)/nointeractive(.+)|(.+)/node(.+)|(.+)/namespace(.+)|(.+)/user(.+)|(.+)Invoke-Item(.+)|(.+)http://(.+)|(.+)/transfer(.+)|(.+)/password(.+)|(.+)administrator(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as loki_proc_sch_res:
                    loki_proc_sch_res.write("[+] Hunting in Loki ProcessScan Module:" + '\n' + (line))
                    loki_proc_sch_res.write('\n')
        for line in match:
            if re.match(r'(.+)/download(.+)|(.+)/addfile(.+)|(.+)/resume(.+)|(.+)/complete(.+)|(.+)myDownloadJob(.+)|(.+)/Create(.+)|(.+)/Delete(.+)|(.+)/run(.+)|(.+)/nointeractive(.+)|(.+)ActiveXObject(.+)|(.+)DeleteFile(.+)|(.+)/gtoconsole=false(.+)|(.+)/logfile=(.+)|(.+)add rule(.+)|(.+)action=allow(.+)|(.+)allowedprogram(.+)|(.+)/delete(.+)|(.+)/fullname(.+)|(.+)/password(.+)|(.+)administrator(.+)|(.+)/grant Everyone(.+)|(.+)/deny Everyone(.+)|(.+)/add(.+)|(.+)/delete(.+)|(.+)/fullname(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as loki_proc_sch_res:
                    loki_proc_sch_res.write("[+] Hunting in Loki ProcessScan Module:" + '\n' + (line))
                    loki_proc_sch_res.write('\n')
    print("%s[+] Finished Hunting in Loki ProcessScan Module%s" % (fg(118), attr(0)))

# hunt inside loki filescan module
def loki_file_hunt():
    print('\n' + '%s[+] Hunting in Loki FileScan Module%s' % (fg(117), attr(0)))
    loki_file_hunt_path = ("Malware\\Loki-Check")
    os.chdir(res_path + '\\' + loki_file_hunt_path) 
    match = []
    final = []
    with open("loki-results.log", "rb") as loki_file_sch:
        for line in loki_file_sch:
            if re.match('(.+)FileScan(.+)', line):
                match.append(line)
        for line in match:
            if re.match('(.+)Warning(.+)|(.+)Alert(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as loki_file_sch_res:
                    loki_file_sch_res.write("[+] Hunting in Loki FileScan Module:" + '\n' + (line))
                    loki_file_sch_res.write('\n')
    print("%s[+] Finished Hunting in Loki FileScan Module%s" % (fg(118), attr(0)))

# hunt inside IIS files
def iis_logs_hunt():
    print('\n' + '%s[+] Hunting in IIS Files%s' % (fg(117), attr(0)))
    iis_hunt_path = ("Logs\IISLogs")
    os.chdir(res_path + '\\' + iis_hunt_path)
    dirpath = os.getcwd()
    final = []
    for filename in os.listdir(dirpath):
        os.chdir(res_path + '\\' + iis_hunt_path)
        if filename.endswith(".log"):
            iis = open(filename)
            iis_sch = iis.readlines()
            for line in iis_sch:
                if re.match(r'(.+)cmd=(.+)|(.+)file=(.+)|(.+)proxy=(.+)|(.+)^dir(.+)|(.+)whomai(.+)|(.+)execute(.+)|(.+)eval(.+)|(.+)username=(.+)|(.+)^password=(.+)|(.+)^pass(.+)|(.+)^command(.+)|(.+)^filename(.+)|(.+)^auth(.+)|(.+)download(.+)|(.+)shell=(.+)|(.+)^func=(.+)|(.+)^output=(.+)|(.+)^port=(.+)|(.+)^sql=(.+)|(.+)Userpwd(.+)|(.+).zip\b(.+)|(.+).rar\b(.+)|(.+).pst\b(.+)|(.+).7z\b(.+)|(.+).dmp\b(.+)|(.+).vmdk\b(.+)|(.+).vhdx\b(.+)|(.+).vhd\b(.+)|(.+).vdi\b(.+)|(.+).hdd\b(.+)', line):
                    final.append(line)
                    sys.stdout.write("------------------------------------\n")
                    sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                    write_hunt_path = ("Hunting")
                    os.chdir(res_path + '\\' + write_hunt_path)
                    with open("Winterfell_Hunt_Report.txt", "a") as iis_sch_res:
                        iis_sch_res.write("[+] Hunting in IIS Files:" + '\n' + (line))
                        iis_sch_res.write('\n')
    print("%s[+] Finished Hunting in IIS Files%s" % (fg(118), attr(0)))

# hunt inside URL history data
def URL_history_hunt():
    print('\n' + '%s[+] Hunting in URL History Data%s' % (fg(117), attr(0)))
    web_hunt_path = ("Web\\Browsing")
    os.chdir(res_path + '\\' + web_hunt_path)
    cmd = 'type URLs-history.csv > URL-history-decoded.txt'
    os.system(cmd)
    final = []
    with open("URL-history-decoded.txt", 'rb') as web_sch:
        for line in web_sch:
            if re.match(r'(.+)///(.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as web_sch_res:
                    web_sch_res.write("[+] Hunting in URL History Data:" + '\n' + (line))
                    web_sch_res.write('\n')
    print("%s[+] Finished Hunting in URL History Data%s" % (fg(118), attr(0)))

# hunt inside dirlisting results
def dirlisting_hunt():
    print('\n' + '%s[+] Hunting in Dirlisting File%s' % (fg(117), attr(0)))
    dir_hunt_path = ("System\\Dirlisting")
    os.chdir(res_path + '\\' + dir_hunt_path) 
    final = []
    with open("dirlisting.txt", "r") as dir_sch:
        for line in dir_sch:
            if re.match(r'(.+).bat\b (.+)|(.+).vbs\b (.+)|(.+).ps1\b (.+)|(.+).exe\b (.+)', line):
                final.append(line)
                sys.stdout.write("------------------------------------\n")
                sys.stdout.write((line) + ('%s[ INVISTGATE ]%s' % (fg(184), attr(0))) + '\n')
                write_hunt_path = ("Hunting")
                os.chdir(res_path + '\\' + write_hunt_path)
                with open("Winterfell_Hunt_Report.txt", "a") as dir_sch_res:
                    dir_sch_res.write("[+] Hunting in Dirlisting File:" + '\n' + (line))
                    dir_sch_res.write('\n')
    print("%s[+] Finished Hunting in Dirlisting File%s" % (fg(118), attr(0)))

# print statistics report with findings counts
def report():
    sys.stdout.write('\n')
    header = ("""                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
██╗  ██╗██╗   ██╗███╗   ██╗████████╗    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗      
██║  ██║██║   ██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝      
███████║██║   ██║██╔██╗ ██║   ██║       ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║         
██╔══██║██║   ██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║         
██║  ██║╚██████╔╝██║ ╚████║   ██║       ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║         
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                                                                                                                                                                                                                                                                                                               
    """)

    print(header)
    sys.stdout.write(('%sWinterfell hunt has completed. Full report is loacted at%s' % (fg(117), attr(0))) + ' '  + cname + ('\Hunting\Winterfell_Hunt_Report.txt' + '\n'))
    sys.stdout.write(('%sResults statstics are the following:%s' % (fg(117), attr(0))) + '\n')
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+]"'
    print('%sTotal Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Amcache File:"'
    print('%sAmcache Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Shellbags File:"'
    print('%sShellbags Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Powershell Logs Files:"'
    print('%sPowershell Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Firewall Rules:"'
    print('%sFirewall Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)        
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Dlls File:"'
    print('%sDlls Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Recycle Bin:"'
    print('%sRecycle Bin Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Prefetch Data:"'
    print('%sPrefetch Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Security Logs:"'
    print('%sSecurity Logs Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Autoruns File:"'
    print('%sAutoruns Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Schedule Tasks:"'
    print('%sSchedule Task Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in UsnJrnl File:"'
    print('%sUsnJrnl Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Loki ProcessScan Module:"'
    print('%sLoki ProcessScan Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Loki FileScan Module:"'
    print('%sLoki FileScan Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in IIS Files:"'
    print('%sIIS Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in URL History Data:"'
    print('%sURL History Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in Dirlisting File:"'
    print('%sDirlisting Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in LOCAL_MACHINE Registry:"'
    print('%sLOCAL_MACHINE Registry Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)
    sys.stdout.write("------------------------------------\n")
    cmd = 'type Winterfell_Hunt_Report.txt | find /c "[+] Hunting in CURRENT_USER Registry:"'
    print('%sCURRENT_USER Registry Findings Count: %s' % (fg(184), attr(0)));os.system(cmd)


amcache_hunt()
bags_hunt()
prefetch_hunt()
security_logs_hunt()
powershell_logs_hunt()
autoruns_hunt()
schedule_tasks_hunt()
firewall_hunt()
dll_hunt()
usnjrnl_hunt()
recycle_bin_hunt()
loki_proc_hunt()
loki_file_hunt()
URL_history_hunt()
dirlisting_hunt()
iis_logs_hunt()
registry_CURRENT_USER_hunt()
registry_LOCAL_MACHINE_hunt()
report()
