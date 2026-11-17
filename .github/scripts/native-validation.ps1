$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'MSVC x64 tools are required.' }
$devcmd = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
# Import the developer environment into this disposable CI process only.
& $env:ComSpec /s /c "`"`"$devcmd`" -arch=x64 -host_arch=x64 >nul && set`"" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
if ($LASTEXITCODE -ne 0) { throw 'Developer environment setup failed.' }
$env:PATH = "${env:ProgramFiles}\LLVM\bin;$env:PATH"
Get-Command cl.exe, clang-cl.exe | ForEach-Object {
    $item = Get-Item $_.Source
    [PSCustomObject]@{ Name = $_.Name; Path = $_.Source; Version = $item.VersionInfo.FileVersion }
}
$env:GO_PE_NATIVE_VALIDATION = '1'
$env:GO_PE_SIGNED_FIXTURE = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
[Environment]::OSVersion.VersionString
go test -count=1 -v -run '^TestNativeWindows' .
if ($LASTEXITCODE -ne 0) { throw 'Native Windows validation failed.' }
