#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include "sample.h"
#include <WtsApi32.h>
#include <iostream>
#include <fstream>
#include "SDDL.h"
#include <thread>
#include <chrono>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "WtsApi32.lib")
#define serviceName TEXT("ServiceSample")

bool Check(BOOL statement);

//std::wofstream log("C:\\Users\\Mi99^\\source\\repos\\start\\DLL2\\service_log.txt");

class ServiceSample {

    SERVICE_STATUS          gSvcStatus;
    SERVICE_STATUS_HANDLE   gSvcStatusHandle;
    //const wchar_t* serviceName = L"ServiceSample";
    HANDLE ghSvcStopEvent;
    HANDLE ghSessionChangeEvent;

public:

    ServiceSample() : gSvcStatusHandle(NULL), ghSvcStopEvent(NULL) {}

    VOID SvcStart()
    {
        BOOL bStartService = FALSE;
        SERVICE_STATUS_PROCESS SvcStatusProcess;
        SC_HANDLE hOpenSCManager = NULL;
        SC_HANDLE hOpenService = NULL;
        BOOL bQueryServiceStatus = FALSE;
        DWORD dwBytesNeeded;

        SC_HANDLE hScOpenSCManager = OpenSCManager(
            NULL,                   // local computer
            NULL,                   // ServicesActive database
            SC_MANAGER_ALL_ACCESS   // full access rights
        );

        if (hScOpenSCManager == NULL)
        {
            std::cout << "OpenSCManager failed: " << GetLastError() << std::endl;
            return;
        }

        SC_HANDLE hScOpenService = OpenService(
            hScOpenSCManager,         // SCM database
            serviceName,       // name of service
            SERVICE_ALL_ACCESS // full access rights
        );

        if (hScOpenService == NULL)
        {
            std::cout << "OpenService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hScOpenSCManager);
            return;
        }

        bQueryServiceStatus = QueryServiceStatusEx(hScOpenService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

        if (bQueryServiceStatus == FALSE) {
            std::cout << "QueryServiceStatus failed " << GetLastError() << std::endl;
        }
        else {
            std::cout << "QueryServiceStatus success" << std::endl;
        }

        if ((SvcStatusProcess.dwCurrentState != SERVICE_STOPPED) && (SvcStatusProcess.dwCurrentState != SERVICE_STOP_PENDING))
        {
            std::cout << "Service stopped" << std::endl;
        }

        while (SvcStatusProcess.dwCurrentState == SERVICE_STOP_PENDING)
        {
            bQueryServiceStatus = QueryServiceStatusEx(hScOpenService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

            if (bQueryServiceStatus == FALSE)
            {
                CloseServiceHandle(hOpenService);
                CloseServiceHandle(hOpenSCManager);
            }
        }

        bStartService = StartService(
            hOpenService,
            NULL,
            NULL
        );

        if (bStartService == FALSE)
        {
            CloseServiceHandle(hOpenService);
            CloseServiceHandle(hOpenSCManager);
        }

        bQueryServiceStatus = QueryServiceStatusEx(hScOpenService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

        if (bQueryServiceStatus == FALSE)
        {
            CloseServiceHandle(hOpenService);
            CloseServiceHandle(hOpenSCManager);
        }

        CloseServiceHandle(hOpenService);
        CloseServiceHandle(hOpenSCManager);

    }

    static DWORD WINAPI SvcCtrlHandler(DWORD dwCtrl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
    {
        
        ServiceSample* service = reinterpret_cast<ServiceSample*>(lpContext);

        // Handle the requested control code. 
        DWORD result = ERROR_CALL_NOT_IMPLEMENTED;

        switch (dwCtrl)
        {
        case SERVICE_CONTROL_STOP:

            service->gSvcStatus.dwCurrentState = SERVICE_STOPPED;
            result = NO_ERROR;
            break;

        case SERVICE_CONTROL_SHUTDOWN:

            service->gSvcStatus.dwCurrentState = SERVICE_STOPPED;
            result = NO_ERROR;
            break;

        case SERVICE_CONTROL_SESSIONCHANGE:
            if (dwEventType == WTS_SESSION_LOGON)
            {
                WTSSESSION_NOTIFICATION* sessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
                ServiceSample::StartUiProcessInSession(sessionNotification->dwSessionId);
            }
            break;

        case SERVICE_CONTROL_INTERROGATE:
            result = NO_ERROR;
            break;
        }

        SetServiceStatus(service->gSvcStatusHandle, &(service->gSvcStatus));

        return result;
    }

    static VOID WINAPI SvcMain(DWORD dwArgc, wchar_t** argv)
    {
        std::ofstream out;
        out.open("C:\\Users\\Mi99^\\source\\repos\\start\\DLL2\\logMain.txt");
        if (out.is_open())
        {
            out << "Welcome" << std::endl;
        }

        ServiceSample* service = new ServiceSample();

        service->gSvcStatusHandle = RegisterServiceCtrlHandlerExW(serviceName, (LPHANDLER_FUNCTION_EX)SvcCtrlHandler, argv[0]);

        if (service->gSvcStatusHandle == (SERVICE_STATUS_HANDLE)0)
        {
            out << "RegisterServiceCtrlHandler failed" << GetLastError() << std::endl;
            delete service;
            return;
        }
        else
        {
            out << "RegisterServiceCtrlHandler success" << std::endl;
        }

        // These SERVICE_STATUS members remain as set here

        service->gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        service->gSvcStatus.dwServiceSpecificExitCode = 0;
        service->gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        service->gSvcStatus.dwCurrentState = SERVICE_RUNNING;

        out << "456" << std::endl;

        service->SvcReportStatus(SERVICE_START_PENDING, NO_ERROR, 0);

       
        SetServiceStatus(service->gSvcStatusHandle, &(service->gSvcStatus));

        PWTS_SESSION_INFOW wtsSessions;
        DWORD sessionsCount;

        out << "fwerwe1213" << std::endl;

        if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wtsSessions, &sessionsCount))
        {
            out << "WTSEnumerateSessionsW returns TRUE, sessionsCount = " << sessionsCount << std::endl;
            for (DWORD i = 0; i < sessionsCount; ++i)
            {

                if (wtsSessions[i].SessionId != 0 && wtsSessions[i].SessionId != 65536)
                {
                    out << "wtsSessions[i].SessionId = " << wtsSessions[i].SessionId << std::endl;
                    ServiceSample::StartUiProcessInSession(wtsSessions[i].SessionId);
                }
            }
        }
        else
        {
            out << "WTSEnumerateSessionsW returns FALSE, error code = " << GetLastError() << std::endl;
        }

        service->SvcInit(dwArgc, argv);

        while (service->gSvcStatus.dwCurrentState != SERVICE_STOPPED)
        {
            out << "Service is start";
            if (WaitForSingleObject(service->ghSvcStopEvent, 60000) != WAIT_TIMEOUT)
                service->SvcReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
        }

        out.close();
    }

    VOID SvcInit(DWORD dwArgc, LPTSTR* lpszArgv)
    {

        ghSvcStopEvent = CreateEvent(
            NULL,    // default security attributes
            TRUE,    // manual reset event
            FALSE,   // not signaled
            NULL);   // no name

        if (ghSvcStopEvent == NULL)
        {
            SvcReportStatus(SERVICE_STOPPED, GetLastError(), 0);
            return;
        }
        else
            SvcReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

        /*while (1)
        {
            WaitForSingleObject(ghSvcStopEvent, INFINITE);
            SvcReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
        }*/
    }


    VOID SvcInstall(TCHAR* szPath)
    {

        SC_HANDLE hOpenSCManager = NULL;
        SC_HANDLE hCreateService = NULL;

        if (!GetModuleFileName(NULL, szPath, MAX_PATH))
        {
            printf("Cannot install service (%d)\n", GetLastError());
            return;
        }
        // In case the path contains a space, it must be quoted so that
        // it is correctly interpreted. For example,
        // "d:\my share\myservice.exe" should be specified as
        // ""d:\my share\myservice.exe"".

        std::cout << szPath << std::endl;


        // Get a handle to the SCM database. 

        hOpenSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database 
            SC_MANAGER_ALL_ACCESS);  // full access rights 

        if (hOpenSCManager == NULL)
        {
            printf("OpenSCManager failed (%d)\n", GetLastError());
            return;
        }

        // Create the service

        hCreateService = CreateService(
            hOpenSCManager,              // SCM database 
            serviceName,                   // name of service 
            serviceName,                   // service name to display 
            SERVICE_ALL_ACCESS,        // desired access 
            SERVICE_WIN32_OWN_PROCESS, // service type 
            SERVICE_DEMAND_START,      // start type 
            SERVICE_ERROR_NORMAL,      // error control type 
            szPath,                    // path to service's binary 
            NULL,                      // no load ordering group 
            NULL,                      // no tag identifier 
            NULL,                      // no dependencies 
            NULL,                      // LocalSystem account 
            NULL);                     // no password 

        if (hCreateService == NULL)
        {
            printf("CreateService failed (%d)\n", GetLastError());
            CloseServiceHandle(hOpenSCManager);
            return;
        }
        else printf("Service installed successfully\n");

        CloseServiceHandle(hCreateService);
        CloseServiceHandle(hOpenSCManager);
    }


    VOID SvcReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, WORD dwWaitHint)
    {
        static DWORD dwCheckPoint = 1;

        // Fill in the SERVICE_STATUS structure.

        BOOL bSetServiceStatus = FALSE;
        gSvcStatus.dwCurrentState = dwCurrentState;
        gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
        gSvcStatus.dwWaitHint = dwWaitHint;

        if (dwCurrentState == SERVICE_START_PENDING)
            gSvcStatus.dwControlsAccepted = 0;
        else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

        if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
            gSvcStatus.dwCheckPoint = 0;
        else gSvcStatus.dwCheckPoint = dwCheckPoint++;

        // Report the status of the service to the SCM.
        bSetServiceStatus = SetServiceStatus(gSvcStatusHandle, &gSvcStatus);

        if (!Check(bSetServiceStatus))
        {
            std::cout << "Service Status failed" << GetLastError() << std::endl;
        }
    }

    VOID SvcReportEvent(LPTSTR szFunction)
    {
        HANDLE hEventSource;
        LPCTSTR lpszStrings[2];
        TCHAR Buffer[80];

        hEventSource = RegisterEventSource(NULL, serviceName);

        if (NULL != hEventSource)
        {
            StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

            lpszStrings[0] = serviceName;
            lpszStrings[1] = Buffer;

            ReportEvent(hEventSource,        // event log handle
                EVENTLOG_ERROR_TYPE, // event type
                0,                   // event category
                SVC_ERROR,           // event identifier
                NULL,                // no security identifier
                2,                   // size of lpszStrings array
                0,                   // no binary data
                lpszStrings,         // array of strings
                NULL);               // no binary data

            DeregisterEventSource(hEventSource);
        }
    }

    VOID SvcStop()
    {
        SERVICE_STATUS_PROCESS SvcStatusProcess;
        DWORD dwBytesNeeded;

        SC_HANDLE hScOpenSCManager = OpenSCManager(
            NULL,                   // local computer
            NULL,                   // ServicesActive database
            SC_MANAGER_ALL_ACCESS   // full access rights
        );

        if (hScOpenSCManager == NULL)
        {
            std::cout << "OpenSCManager failed: " << GetLastError() << std::endl;
            return;
        }

        SC_HANDLE hScOpenService = OpenService(
            hScOpenSCManager,         // SCM database
            serviceName,       // name of service
            SERVICE_ALL_ACCESS // full access rights
        );

        if (hScOpenService == NULL)
        {
            std::cout << "OpenService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hScOpenSCManager);
            return;
        }

        BOOL bQueryServiceStatus = QueryServiceStatusEx(hScOpenService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

        if (!bQueryServiceStatus)
        {
            std::cout << "QueryServiceStatus failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hScOpenService);
            CloseServiceHandle(hScOpenSCManager);
            return;
        }

        BOOL bControlService = ControlService(hScOpenService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&SvcStatusProcess);

        if (!bControlService)
        {
            std::cout << "ControlService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hScOpenService);
            CloseServiceHandle(hScOpenSCManager);
            return;
        }

        while (SvcStatusProcess.dwCurrentState != SERVICE_STOPPED)
        {
            bQueryServiceStatus = QueryServiceStatusEx(hScOpenService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

            if (!bQueryServiceStatus)
            {
                CloseServiceHandle(hScOpenService);
                CloseServiceHandle(hScOpenSCManager);
                return;
            }

            if (SvcStatusProcess.dwCurrentState == SERVICE_STOPPED)
            {
                std::cout << "Service stopped successfully" << std::endl;
                break;
            }
            else
            {
                std::cout << "Service stopped failed: " << GetLastError() << std::endl;
                CloseServiceHandle(hScOpenService);
                CloseServiceHandle(hScOpenSCManager);
            }
        }

        CloseServiceHandle(hScOpenService);
        CloseServiceHandle(hScOpenSCManager);
    }


    VOID SvcDelete()
    {
        SC_HANDLE hSCManager = OpenSCManager(
            NULL,                   // local computer
            NULL,                   // ServicesActive database
            SC_MANAGER_ALL_ACCESS   // full access rights
        );

        if (hSCManager == NULL)
        {
            std::cout << "OpenSCManager failed: " << GetLastError() << std::endl;
            return;
        }

        SC_HANDLE hService = OpenService(
            hSCManager,         // SCM database
            serviceName,       // name of service
            SERVICE_ALL_ACCESS // full access rights
        );

        if (hService == NULL)
        {
            std::cout << "OpenService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return;
        }

        BOOL bDeleteService = DeleteService(hService);
        if (!bDeleteService)
        {
            std::cout << "Delete service failed: " << GetLastError() << std::endl;
        }
        else
        {
            std::cout << "Delete service success" << std::endl;
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
    }

    static void StartUiProcessInSession(DWORD wtsSession)
    {
        std::ofstream out;
        out.open("C:\\Users\\Mi99^\\source\\repos\\start\\DLL2\\logCreateProcess.txt");
        if (out.is_open())
        {
            out << "Welcome" << std::endl;
        }
        out << "wtsSession = " << wtsSession << std::endl;
        HANDLE userToken;
        if (WTSQueryUserToken(wtsSession, &userToken))
        {
            
            WCHAR commandLine[] = L"\"C:\\Windows\\System32\\cmd.exe";
            WCHAR localSystemSddl[] = L"O:SYG:SYD:";
            PROCESS_INFORMATION pi{};
            STARTUPINFO si{};

            SECURITY_ATTRIBUTES processSecurityAttributes{};
            processSecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
            processSecurityAttributes.bInheritHandle = TRUE;

            SECURITY_ATTRIBUTES threadSecurityAttributes{};
            threadSecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
            threadSecurityAttributes.bInheritHandle = TRUE;

            PSECURITY_DESCRIPTOR psd = nullptr;

            out << "Starting " << "\"C:\\Windows\\System32\\cmd.exe" << std::endl;

            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(localSystemSddl, SDDL_REVISION_1, &psd, nullptr)) 
            {
                processSecurityAttributes.lpSecurityDescriptor = psd;
                threadSecurityAttributes.lpSecurityDescriptor = psd;

                if (CreateProcessAsUserW(
                    userToken, 
                    NULL, 
                    commandLine, 
                    &processSecurityAttributes, 
                    &threadSecurityAttributes, 
                    FALSE, 
                    0, 
                    NULL, 
                    NULL, 
                    &si, 
                    &pi))
                {
                    out << "Process started pid = " << pi.dwProcessId << std::endl;

                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                else
                {
                    out << "Failed to start process. Error code = " << GetLastError() << std::endl;
                }

                //CloseHandle(userToken);
                LocalFree(psd);
            }
            else
            {
                out << "Failed Security Descriptor. Error code = " << GetLastError() << std::endl;
            }
        }
        else
        {
            out << "WTSQueryUserToken failed. Error code = " << GetLastError() << std::endl;
        }  
        out.close();
    }

};

int __cdecl _tmain(int argc, TCHAR* argv[])
{
    std::ofstream out;
    out.open("C:\\Users\\Mi99^\\source\\repos\\start\\DLL2\\log.txt");
    if (out.is_open())
    {
        out << "Welcome" << std::endl;
    }

    ServiceSample service;

    out << "main func Start" << std::endl;

    for (int i = 0; i < argc; i++)
        std::wcout << L"\"" << argv[i] << L"\" ";

    if (argc > 1) {
        if (lstrcmpi(argv[1], TEXT("install")) == 0)
        {
            service.SvcInstall(argv[0]);
            return 0;
        }
        else if (lstrcmpi(argv[1], TEXT("start")) == 0)
        {
            service.SvcStart();
            return 0;
        }
        else if (lstrcmpi(argv[1], TEXT("stop")) == 0)
        {
            service.SvcStop();
            return 0;
        }
        else if (lstrcmpi(argv[1], TEXT("delete")) == 0)
        {
            service.SvcDelete();
            return 0;
        }
    }
    else
    {
        SERVICE_TABLE_ENTRY ServiceTable[2];
        ServiceTable[0].lpServiceName = (LPWSTR)serviceName;
        ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceSample::SvcMain;
        ServiceTable[1].lpServiceName = NULL;
        ServiceTable[1].lpServiceProc = NULL;


        if (!StartServiceCtrlDispatcher(ServiceTable)) {
            std::cerr << "Error: StartServiceCtrlDispatcher: " << GetLastError();
        }
    }

    
    
    out.close();
    
    return 0;
}

bool Check(BOOL statement)
{
    if (statement == FALSE)
    {
        return false;
    }
    return true;
}
