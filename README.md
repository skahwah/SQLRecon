# SQLRecon

## Description
A C# MS-SQL toolkit designed for offensive reconnaissance and post-exploitation. For detailed usage information on each technique, refer to the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>. 


# Usage
You can grab a copy of SQLRecon from the [releases](https://github.com/skahwah/SQLRecon/releases) page. Alternatively, feel free to compile the solution yourself This should be as straight forward as cloning the repo, double clicking the solution file and building.

## Mandatory Arguments

The mandatory arguments consist of an authentication type (either Windows, Local or Azure), connection parameters and a module.

* <b>-a</b> - Authentication Type
  * <b>-a Windows</b> - Use Windows authentication. This uses the current users token.
  * <b>-a Local</b> - Use local authentication. This requires the credentials for a local database user.
  * <b>-a Azure</b> - Use Azure AD domain username and password authentication. This requires the credentials for a domain user.

If the authentication type is <b>Windows</b>, then you will need to supply the following parameters.
  * <b>-s SERVERNAME</b> - SQL server hostname
  * <b>-d DATABASE</b> - SQL server database name
  * <b>-m MODULE</b> - The module you want to use

If the authentication type is <b>Local</b>, then you will need to supply the following parameters.
  * <b>-d DATABASE</b> - SQL server database name
  * <b>-u USERNAME</b> - Username of local SQL user
  * <b>-p PASSWORD</b> - Password of local SQL user
  * <b>-m MODULE</b> - The module you want to use

If the authentication type is <b>Azure</b>, then you will need to supply the following parameters.
* <b>-d DATABASE</b> - SQL server database name
* <b>-r DOMAIN.COM</b> - FQDN of Domain
* <b>-u USERNAME</b> - Username of domain user
* <b>-p PASSWORD</b> - Password of domain user
* <b>-m MODULE</b> - The module you want to use

## Standard Modules
Standard modules are used to interact against a single MS SQL server.

* <b>query -o QUERY</b> - Execute an arbitrary SQL query
* <b>whoami</b> - See what user you are logged in as
* <b>mapped</b> - See what user you are mapped to
* <b>roles</b> - Enumerate if the user has public and/or sysadmin roles mapped
* <b>databases</b> - Show all databases present on the SQL server
* <b>tables</b> - Show all tables in the database you are connected to
* <b>search -o KEYWORD</b> - Search column names within tables of the database you are connected to.
* <b>smb -o SHARE</b> - Capture NetNTLMv2 hash
* <b>enablexp</b> - Enable xp_cmdshell (requires sysadmin role or similar)
* <b>disablexp</b> - Disable xp_cmdshell (requires sysadmin role or similar)
* <b>xpcmd -o COMMAND</b> - Execute an arbitrary system command (requires sysadmin role or similar)
* <b>enableole</b> - Enable OLE Automation Procedures (requires sysadmin role or similar)
* <b>disableole</b> - Disable OLE Automation Procedures (requires sysadmin role or similar)
* <b>olecmd -o COMMAND</b> - Execute an arbitrary system command (requires sysadmin role or similar)
* <b>enableclr</b> - Enable Custom CLR Assemblies (requires sysadmin role or similar)
* <b>disableclr</b> - Disable Custom CLR Assemblies (requires sysadmin role or similar)
* <b>impersonate</b> - Enumerate any user accounts that can be impersonated
* <b>links</b> - Enumerate any linked SQL servers

## Impersonation Modules
Impersonation modules are used to interact against a single MS SQL server, under the context of an impersonated SQL user.

* <b>iquery -i IMPERSONATEUSER -o QUERY</b> - Execute an arbitrary SQL query as an impersonated user
* <b>ienablexp -i IMPERSONATEUSER</b> - Enable xp_cmdshell (requires sysadmin role or similar)
* <b>idisablexp -i IMPERSONATEUSER</b>- Disable xp_cmdshell (requires sysadmin role or similar)
* <b>ixpcmd -i IMPERSONATEUSER -o COMMAND</b> - Execute an arbitrary system command (requires sysadmin role or similar)
* <b>ienableole -i IMPERSONATEUSER</b> - Enable OLE Automation Procedures (requires sysadmin role or similar)
* <b>idisableole -i IMPERSONATEUSER</b> - Disable OLE Automation Procedures (requires sysadmin role or similar)
* <b>iolecmd -i IMPERSONATEUSER -o COMMAND</b> - Execute an arbitrary system command (requires sysadmin role or similar)

## Linked SQL Server Modules
Linked SQL Server modules are effective when you are able to interact with a linked SQL server via an established connection.
* <b>lquery -l LINKEDSERVERNAME -o QUERY</b> - Execute an arbitary SQL query on the linked SQL server
* <b>lwhoami</b> - See what user you are logged in as on the linked SQL server
* <b>lroles</b> - Enumerate if the linked SQL server user has public and/or sysadmin roles mapped
* <b>ldatabases -l LINKEDSERVERNAME</b> - Show all databases present on the linked SQL server
* <b>ltables -l LINKEDSERVERNAME -o DATABASE</b> - Show all tables in the supplied database on the linked SQL server
* <b>lsmb -l LINKEDSERVERNAME -o SHARE</b> - Capture NetNTLMv2 hash from linked SQL server

## Examples
See the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>.  for detailed examples.

## Roadmap
The below techniques are on the roadmap for future releases
* Command Execution: Custom Extended Stored Procedures <a href="https://stackoverflow.com/questions/12749210/how-to-create-a-simple-dll-for-a-custom-sql-server-extended-stored-procedure">Reference 1</a>, <a href="https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/MSSQL/xp_evil_template.cpp">Reference 2</a>
* Command Execution: Custom CLR Assemblies <a href="https://www.netspi.com/blog/technical/adversary-simulation/attacking-sql-server-clr-assemblies/">Reference 1</a>
* Command Execution: Agent Jobs <a href="https://github.com/SofianeHamlaoui/Pentest-Notes/blob/master/Security_cheatsheets/databases/sqlserver/3-command-execution.md#agent-jobs-cmdexec-powershell-activex-etc">Reference 1</a>

## History
<b>v1.2</b>
* Created lsmb module
* Created lwhoami module
* Created lroles module

<b>v1.1</b>
* Fixed oldcmd module
* Fixed iolecmd module
* Fixed ldatabases module
* Fixed ltables module
* Cleaned up code base
* Corrected inconsistencies in help menu
