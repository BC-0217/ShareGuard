' Starts the ShareGuard GUI from source with pythonw (no console window).
' Requires Python 3.11+ on PATH. ASCII only.
Option Explicit
Dim fso, shell, here
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)
shell.Run "pythonw """ & here & "\launch_gui.pyw""", 0, False
