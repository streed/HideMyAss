HideMyAss
=========

Is a simple user-mode method of hiding loaded modules within the PEB structure of another running process. 
It also provides functionality to hide files in processes that use the FindFirstFileExW and FindNextFileW functions.
It also provides functionality to hide a process from another process, such as Task Manager, by hooking the NtQuerySystemInformation
function call and remove the process based on a process name as associated with a specific registry key.

This will hide the DLL from simple tools such as OllyDbg and other basic debuggers that do not analyse the entirety of the
PEB memory location for holes or unlinked nodes. It also will not hide files from the command line or disallow users from
navigating to a hidden folder directly, this would require hooking into different functions instead of the chosen ones above.
It also directly relies on the implementation of NtQuerySystemInformation which can change and does change between OS versions.


