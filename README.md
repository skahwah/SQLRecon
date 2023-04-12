# SQLRecon

## Description
A C# MS-SQL toolkit designed for offensive reconnaissance and post-exploitation. For detailed usage information on each technique, refer to the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>. 

# Usage
You can grab a copy of SQLRecon from the [releases](https://github.com/skahwah/SQLRecon/releases) page. Alternatively, feel free to compile the solution yourself This should be as straight forward as cloning the repo, double clicking the solution file and building.

## Enumeration
SQLRecon supports enumeration of Active Directory for MSSQL SPNs, akin to [PowerUpSQL's](https://github.com/NetSPI/PowerUpSQL) `Get-SQLInstanceDomain`.

* <b>-e</b> - Enumeration Type
  * <b>domain -d DOMAIN | (OPTIONAL) Domain FQDN</b> - Use the current users token to enumerate AD for MSSQL SPNs.

## Mandatory Arguments

The mandatory arguments consist of an authentication type (either Windows, Local or Azure), connection parameters and a module.

* <b>-a</b> - Authentication Type
  * <b>-a Windows</b> - Use Windows authentication. This uses the current users token.
  * <b>-a Local</b> - Use local authentication. This requires the credentials for a local database user.
  * <b>-a Azure</b> - Use Azure AD domain username and password authentication. This requires the credentials for a domain user.

If the authentication type is <b>Windows</b>, then you will need to supply the following parameters.
  * <b>-s SERVERNAME</b> - SQL server hostname
  * <b>-d DATABASE</b> - (OPTIONAL) SQL server database name, defaults to 'master'
  * <b>-m MODULE</b> - The module you want to use

If the authentication type is <b>Local</b>, then you will need to supply the following parameters.
  * <b>-d DATABASE</b> - (OPTIONAL) SQL server database name, defaults to 'master'
  * <b>-u USERNAME</b> - Username of local SQL user
  * <b>-p PASSWORD</b> - Password of local SQL user
  * <b>-m MODULE</b> - The module you want to use

If the authentication type is <b>Azure</b>, then you will need to supply the following parameters.
  * <b>-d DATABASE</b> - (OPTIONAL) SQL server database name, defaults to 'master'
  * <b>-r DOMAIN.COM</b> - FQDN of Domain
  * <b>-u USERNAME</b> - Username of domain user
  * <b>-p PASSWORD</b> - Password of domain user
  * <b>-m MODULE</b> - The module you want to use

There are cases where a MS SQL Server might not be listening on a standard TCP port. A good example is MS SQL failover clustering. If the authentication type is <b>Windows</b> or <b>Local</b>, you can optionally set a non-standard connection port by supplying the <b>-r PORT</b> flag. By default, SQLRecon will connect to a databases via TCP Port 1433.

## Standard Modules
Standard modules are used to interact against a single MS SQL server.

* <b>info</b> - Print information about the SQL Service
* <b>query -o QUERY</b> - Execute an arbitrary SQL query
* <b>whoami</b> - See what user you are logged in as, mapped as and what roles exist
* <b>users</b> - See what user accounts and groups can authenticate against the database
* <b>databases</b> - Show all databases present on the SQL server
* <b>tables -o DATABASE</b> - Show all tables in the database you specify
* <b>search -o KEYWORD</b> - Search column names within tables of the database you are connected to
* <b>smb -o SHARE</b> - Capture NetNTLMv2 hash
<br>↓ Command Execution (requires sysadmin role or similar)
* <b>enablexp</b> - Enable xp_cmdshell
* <b>disablexp</b> - Disable xp_cmdshell
* <b>xpcmd -o COMMAND</b> - Execute an arbitrary system command using xp_cmdshell
* <b>enableole</b> - Enable OLE Automation Procedures
* <b>disableole</b> - Disable OLE Automation Procedures
* <b>olecmd -o COMMAND</b> - Execute an arbitrary system command using OLE Automation Procedures
* <b>enableclr</b> - Enable Custom CLR Assemblies
* <b>disableclr</b> - Disable Custom CLR Assemblies
* <b>clr -o DLLPATH -f FUNCTION</b> - Load and execute a .NET assembly within a custom stored procedure
* <b>agentstatus</b> - Check to see if SQL agent is running and obtain jobs
* <b>agentcmd -o COMMAND</b> - Execute an arbitary system command

## Impersonation Modules
Impersonation modules are used to interact against a single MS SQL server, under the context of an impersonated SQL user.
* <b>impersonate</b> - Enumerate any user accounts that can be impersonated
* <b>iwhoami -i IMPERSONATEUSER</b> - See what user you are logged in as, mapped as and what roles exist
* <b>iusers -i IMPERSONATEUSER</b> - See what user accounts and groups can authenticate against the database
* <b>iquery -i IMPERSONATEUSER -o QUERY</b> - Execute an arbitrary SQL query as an impersonated user
<br>↓ Command Execution (requires sysadmin role or similar)
* <b>ienablexp -i IMPERSONATEUSER</b> - Enable xp_cmdshell
* <b>idisablexp -i IMPERSONATEUSER</b>- Disable xp_cmdshell
* <b>ixpcmd -i IMPERSONATEUSER -o COMMAND</b> - Execute an arbitrary system command using xp_cmdshell
* <b>ienableole -i IMPERSONATEUSER</b> - Enable OLE Automation Procedures
* <b>idisableole -i IMPERSONATEUSER</b> - Disable OLE Automation Procedures
* <b>iolecmd -i IMPERSONATEUSER -o COMMAND</b> - Execute an arbitrary system command  using OLE Automation Procedures
* <b>ienableclr</b> - Enable Custom CLR Assemblies
* <b>idisableclr</b> - Disable Custom CLR Assemblies
* <b>iclr -o DLLPATH -f FUNCTION</b> - Load and execute a .NET assembly within a custom stored procedure
* <b>iagentstatus -i IMPERSONATEUSER</b> - Check to see if SQL agent is running and obtain jobs
* <b>iagentcmd -i IMPERSONATEUSER -o COMMAND</b> - Execute an arbitary system command

## Linked SQL Server Modules
Linked SQL Server modules are effective when you are able to interact with a linked SQL server via an established connection.
* <b>links</b> - Enumerate any linked SQL servers
* <b>lquery -l LINKEDSERVERNAME -o QUERY</b> - Execute an arbitrary SQL query on the linked SQL server
* <b>lwhoami -l LINKEDSERVERNAME</b> - See what user you are logged in as on the linked SQL server
* <b>lusers -l LINKEDSERVERNAME</b> - See what user accounts and groups can authenticate against the database on the linked SQL server
* <b>ldatabases -l LINKEDSERVERNAME</b> - Show all databases present on the linked SQL server
* <b>ltables -l LINKEDSERVERNAME -o DATABASE</b> - Show all tables in the supplied database on the linked SQL server
* <b>lsmb -l LINKEDSERVERNAME -o SHARE</b> - Capture NetNTLMv2 hash from linked SQL server
<br>↓ Command Execution (requires sysadmin role or similar)
* <b>lenablerpc -l LINKEDSERVERNAME</b> - Enable RPC and RPC out on a linked SQL server
* <b>ldisablerpc -l LINKEDSERVERNAME</b> - Disable RPC and RPC out on a linked SQL server
* <b>lenablexp -l LINKEDSERVERNAME</b> - Enable xp_cmdshell on the linked SQL server
* <b>ldisablexp -l LINKEDSERVERNAME</b> - Disable xp_cmdshell on the linked SQL server
* <b>lxpcmd -l LINKEDSERVERNAME -o COMMAND</b> - Execute an arbitrary system command using xp_cmdshell on the linked SQL server
* <b>lenableole -l LINKEDSERVERNAME</b> - Enable OLE Automation Procedures on the linked SQL server
* <b>ldisableole -l LINKEDSERVERNAME</b> - Disable OLE Automation Procedures on the linked SQL server
* <b>lolecmd -l LINKEDSERVERNAME -o COMMAND</b> - Execute an arbitrary system command using OLE Automation Procedures on the linked SQL server
* <b>lenableclr -l LINKEDSERVERNAME</b> - Enable Custom CLR Assemblies on the linked SQL server
* <b>ldisableclr -l LINKEDSERVERNAME</b> - Disable Custom CLR Assemblies on the linked SQL server
* <b>lclr -o DLLPATH -f FUNCTION</b> - Load and execute a .NET assembly within a custom stored procedure on the linked SQL server
* <b>lagentstatus -l LINKEDSERVERNAME</b> - Check to see if SQL agent is running and obtain jobs on the linked SQL server
* <b>lagentcmd -l LINKEDSERVERNAME -o COMMAND</b> - Execute an arbitrary system command on the linked SQL server

## Examples
See the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>.  for detailed examples.

## Roadmap
The below techniques are on the roadmap for future releases
* Expand enumeration modules

## History
<details>
<summary>v2.2.2</summary>

* Fixed checking RPC status on linked SQL servers.
</details>

<details>
<summary>v2.2.1</summary>

* Added the capability to download .NET assemblies via HTTP/S
</details>

<details>
<summary>v2.2</summary>

* Expanded roles which are queried in the roles, iroles and lroles modules
* Created users, iusers and lusers modules
* Fixed hash not being dropped from sp_drop_trusted_assembly in clr and iclr modules
* Created lagentcmd module
* Created lclr module
</details>

<details>
<summary>v2.1.6</summary>

* Added 'info' module, '-m info'.
* Corrections in Help.cs.
* Resolved issues with mandatory arguments with Local and Azure authentication.
</details>

<details>
<summary>v2.1.5</summary>

* Added option to enumerate domain SPNs (-e domain).
</details>

<details>
<summary>v2.1.4</summary>

* Fixed minor string formatting issue.
</details>

<details>
<summary>v2.1.3</summary>

* Added '-r' flag into Windows and Local authentication modes so that non-standard TCP ports can be supplied.
</details>

<details>
<summary>v2.1.2</summary>

* Improved logic around null connection strings
</details>

<details>
<summary>v2.1.1</summary>

* Removed Environment.Exit from TestAuthentication.cs
</details>

<details>
<summary>v2.1</summary>

* Created AgentJobs.cs
* Created agentstatus
* Created iagentstatus
* Created lagentstatus
* Created agentcmd
* Created iagentcmd
</details>

<details>
<summary>v2.0</summary>

* Created clr
* Created ienableclr
* Created idisbleclr
* Created iclr
* Created iwhoami
* Created imapped
* Created iroles
* Created lenablerpc
* Created ldisablerpc
* Created lwhoai
* Created lenablexp
* Created ldisablexp
* Created lenableole
* Created ldisableole
* Created lenableclr
* Created ldisableclr
* Created lxpcmd
* Created lxpole
* Created Random.cs
* Created EnableDisable.cs
* Implemented randomly generated assembly names for clr
* Implemented randomly generated variable and method names for ole
* Rolled 'mapped' and 'roles' modules into 'whoami'
* Rolled 'lmapped' and 'lroles' modules into 'lwhoami'
* Rolled 'imapped' and 'iroles' modules into 'iwhoami'
* Re-factored complete code base
</details>

<details>
<summary>v1.2</summary>

* Created lsmb module
* Created lwhoami module
* Created lroles module
</details>

<details>
<summary>v1.1</summary>

* Fixed oldcmd module
* Fixed iolecmd module
* Fixed ldatabases module
* Fixed ltables module
* Cleaned up code base
* Corrected inconsistencies in help menu
</details>
