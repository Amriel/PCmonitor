' ============================================================
'  PC Monitor - start silently in the background (no console).
'  Uses pythonw.exe so nothing appears on the taskbar.
'  The monitor keeps running and shows a tray icon (if pystray
'  is installed). Open the window any time with open.bat.
' ============================================================
Option Explicit
Dim fso, sh, here, py, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = here

' Prefer pythonw.exe (no console). Fall back to python.exe hidden.
py = ""
On Error Resume Next
Dim exec, line
Set exec = sh.Exec("where pythonw.exe")
Do While Not exec.StdOut.AtEndOfStream
  line = Trim(exec.StdOut.ReadLine())
  If py = "" And line <> "" Then py = line
Loop
On Error GoTo 0

If py = "" Then
  ' fall back to launcher / python, still hidden (0 = hidden window)
  sh.Run "cmd /c py -3 """ & here & "\monitor.py"" --quiet", 0, False
Else
  sh.Run """" & py & """ """ & here & "\monitor.py"" --quiet", 0, False
End If
