import os
import servicemanager
import shutil
import subprocess
import sys

import win32event
import win32service
import win32serviceutil

SRCDIR = 'c:\\users\\eric\\desktop'
TGTDIR = 'c:\\windows\\temp'

class WinService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'WinService'
    _svc_display_name_ = 'Windows Service'
    _svc_description_ = 'Executes VBScripts at regular intervals.'

    # framework for service, define script location and create event object
    def __init__(self, args):
        self.vbs = os.path.join(TGTDIR, 'winservice_task.vbs')
        self.timeout = 1000 * 60 # 1 minute

        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    # set service status and stop service
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    # start service and execute main function
    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        self.main()

    def main(self):
        # loop runs every minute until stop signal received
        while True:
            ret_code = win32event.WaitForSingleObject(self.hWaitStop, self.timeout)
            if ret_code == win32event.WAIT_OBJECT_0:
                servicemanager.LogInfoMsg("Service is stopping.")
                break
            src = os.path.join(SRCDIR, 'winservice_task.vbs')
            shutil.copy(src, self.vbs)
            # copy script to target dir, execute, delete script
            subprocess.call("cscript.exe %s" % self.vbs, shell=False)
            os.unlink(self.vbs)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(WinService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(WinService)