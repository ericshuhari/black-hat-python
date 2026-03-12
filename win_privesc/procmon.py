import os
import sys
import win32api
import win32con
import win32security
import wmi

def get_process_privileges(pid):
    try:
        # obtain handle to target process
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        # obtain handle to process token
        htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)
        # query token for enabled privileges, return list of privilege names
        privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)
        privileges = ''
        for priv_id, flags in privs:
            # check if privilege is enabled
            if flags == (win32security.SE_PRIVILEGE_ENABLED | 
                        win32security.SE_PRIVILEGE_ENABLED_BY_DEFAULT):
                # lookup human-readable privilege name and append to string
                privileges += f'{win32security.LookupPrivilegeName(None, priv_id)}|'
    except Exception as e:
        print(f'Error retrieving privileges: {e}')
        privileges = 'N/A'
        return privileges

def log_to_file(message):
    with open('process_monitor_log.csv', 'a') as fd:
        fd.write(f'{message}\r\n')

def monitor():
    head = 'CommandLine, Time, Executable, Parent PID, PID, User, Privileges'
    log_to_file(head)
    # instantiate WMI class
    c = wmi.WMI()
    # watch for process creation events
    process_watcher = c.Win32_Process.watch_for("creation")
    while True:
        # block until process_watcher returns a new process creation event
        try:
            new_process = process_watcher()
            cmdline = new_process.CommandLine
            create_date = new_process.CreationDate
            executable = new_process.ExecutablePath
            parent_pid = new_process.ParentProcessId
            pid = new_process.ProcessId
            # get process owner
            proc_owner = new_process.GetOwner()

            privileges = get_process_privileges(pid)
            process_log_message = (
                f'{cmdline}, {create_date}, {executable}, ' 
                f'{parent_pid}, {pid}, {proc_owner}, {privileges}'
                )
            print(process_log_message)
            print()
            log_to_file(process_log_message)
        except Exception as e:
            print(f"Error monitoring process: {e}")
            pass

if __name__ == '__main__':
    try:
        monitor()
    except KeyboardInterrupt:
        print(f'Writing to log file {os.path.abspath("process_monitor_log.csv")}')
