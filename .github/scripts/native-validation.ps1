$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'MSVC x64 tools are required.' }
# Import the developer environment into this disposable CI process only.
Import-Module (Join-Path $installation 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $installation -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
$env:PATH = "${env:ProgramFiles}\LLVM\bin;$env:PATH"
Get-Command cl.exe, clang-cl.exe | ForEach-Object {
    $item = Get-Item $_.Source
    [PSCustomObject]@{ Name = $_.Name; Path = $_.Source; Version = $item.VersionInfo.FileVersion }
} | Format-List | Out-String | Write-Host
$env:GO_PE_NATIVE_VALIDATION = '1'
$env:GO_PE_SIGNED_FIXTURE = (Get-Command cl.exe).Source
[Environment]::OSVersion.VersionString
go test -count=1 -v -run '^TestNativeWindows' .
if ($LASTEXITCODE -ne 0) { throw 'Native Windows validation failed.' }
