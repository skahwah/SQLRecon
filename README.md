 &nbsp;
[![licence badge]][licence] 
[![wiki Badge]][wiki] 
[![stars badge]][stars] 
[![forks badge]][forks] 
[![issues badge]][issues] 

[licence badge]:https://img.shields.io/badge/License-BSD_3--Clause-blue.svg
[stars badge]:https://img.shields.io/github/stars/skahwah/SQLRecon.svg
[forks badge]:https://img.shields.io/github/forks/skahwah/SQLRecon.svg
[issues badge]:https://img.shields.io/github/issues/skahwah/SQLRecon.svg
[wiki badge]:https://img.shields.io/badge/SQLRecon-Wiki-green.svg

[licence]:https://github.com/skahwah/SQLRecon/blob/main/LICENSE
[stars]:https://github.com/skahwah/SQLRecon/stargazers
[forks]:https://github.com/skahwah/SQLRecon/network
[issues]:https://github.com/skahwah/SQLRecon/issues
[wiki]:https://github.com/skahwah/SQLRecon/wiki

# SQLRecon

<p align="center">
  <img src="./images/sqlrecon-40.png">
</p>

SQLRecon is a Microsoft SQL Server toolkit that is designed for offensive reconnaissance and post-exploitation. For detailed information on how to use each technique, refer to the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>. 

You can download a copy of SQLRecon from the [releases](https://github.com/skahwah/SQLRecon/releases) page. Alternatively, feel free to compile the solution yourself. This should be as straight forward as cloning the repo, double clicking the solution file and building.

<a href="https://github.com/skahwah/SQLRecon/wiki/9.-Prevention,-Detection-and-Mitigation-Guidance">Prevention, detection and mitigation guidance</a> has also been provided for all you defenders out there.

Check out my blog post on the <a href="https://securityintelligence.com/posts/databases-beware-abusing-microsoft-sql-server-with-sqlrecon/">IBM Security Intelligence</a> website. If you prefer videos, then check out my <a href="https://www.youtube.com/watch?v=LsYSePobFWA">presentation at Black Hat</a>.

# Enumeration Modules

Enumeration Modules do not require an authentication provider to be supplied. These modules must be passed into the enumeration module flag (`/e:, /enum:`). The wiki has details on using <a href="https://github.com/skahwah/SQLRecon/wiki/1.-Enumeration">enumeration modules</a>.

```
Info    - Show information about the SQL server.
          /h:, /host    -> SQL server hostname or IP. Multiple hosts supported.
          /port:        -> (OPTIONAL) Defaults to 1434 (UDP).
          /t:, timeout: -> (OPTIONAL) Defaults to 3s.

SqlSpns - Use the current user token to enumerate the AD domain for MSSQL SPNs.
          /d:, /domain: -> (OPTIONAL) NETBIOS name or FQDN of domain.
```

# Authentication Providers

SQLRecon supports a diverse set of authentication providers (`/a:, /auth:`) to enable interacting with a Microsoft SQL Server.

```
WinToken   - Use the current users token to authenticate against the SQL database
             /h:, /host:     -> SQL server hostname or IP

WinDomain  - Use AD credentials to authenticate against the SQL database
             /h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.
             /d:, /domain:   -> NETBIOS name or FQDN of domain.
             /u:, /username: -> Username for domain user.
             /p:, /password: -> Password for domain user.

Local      - Use local SQL credentials to authenticate against the SQL database
             /h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.
             /u:, /username: -> Username for local SQL user.
             /p:, /password: -> Password for local SQL user.

EntraID    - Use Azure EntraID credentials to authenticate against the Azure SQL database
             /h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.
             /d:, /domain:   -> FQDN of domain (DOMAIN.COM).
             /u:, /username: -> Username for domain user.
             /p:, /password: -> Password for domain user.

AzureLocal - Use local SQL credentials to authenticate against the Azure SQL database
             /h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.
             /u:, /username: -> Username for local SQL user.
             /p:, /password: -> Password for local SQL user.
```

### Authentication Providers - Additional Details

- **Hosts**: The host flag (`/h:, host:`) is required and allows one or more SQL servers. If you want to execute a module against multiple SQL servers, separate the hosts with a comma, for example `/h:SQL01,10.10.10.2,SQL03`.
- **Database**: SQLRecon connects to the `master` database by default, however, this can be optionally changed by supplying a custom database name via the database (`/database:`) flag.
- **Debug**: The `/debug` flag is optional and displays all SQL queries that are executed by a module, without actually executing them on the remote host(s). An example of this can be found in the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>.
- **Port**: In some cases, a Microsoft SQL Server may not be listening on a standard TCP port. Some examples are Microsoft SQL Server failover clustering, or dynamic TCP ports. SQLRecon connects to databases via TCP Port `1433` by default, however, this can be optionally changed using the `/port:` flag.
- **Timeout**: The default SQL database connection time is `3` seconds, however, this value can be optionally changed by supplying a timeout value (`/t:, /timeout:`) which corresponds to the number of seconds before terminating the connection attempt.
- **Verbose**: The `/v, /verbose` flag is optional and displays all SQL queries that are executed by a module before executing them on the remote host(s). An example of this can be found in the <a href="https://github.com/skahwah/SQLRecon/wiki">wiki</a>.

Please note that the `EntraID` authentication provider requires that the Azure Active Directory Authentication Library (ADAL) or Microsoft Authentication Library (MSAL) exists on the system SQLRecon is executed from. This is for Azure EntraID authentication and authorization functionality.

# SQL Modules

SQL modules are executed against one or more instance of Microsoft SQL server. These modules must be passed into the module flag (`/m:, /module:`).

| Module Name | Description | Impersonation | Linked Execution | Linked Chain Execution | Requires Privileged Context |
| ----------- | ----------- | ------------- | ---------------- | ---------------------- | --------------------------- |
| `CheckRpc` | Obtain a list of linked servers and their RPC status. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Databases` | Display all databases. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Impersonate` | Enumerate user accounts that can be impersonated. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Info` | Show information about the SQL server. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Links` | Enumerate linked SQL servers. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Users` | Display what user accounts and groups can authenticate against the database. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Whoami` | Display your privileges. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Query /c:QUERY` | Execute a SQL query. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Smb /unc:UNC_PATH` | Capture NetNTLMv2 hash. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Columns /db:DATABASE /table:TABLE` | Display all columns in the supplied database and table. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Rows /db:DATABASE /table:TABLE` | Display the number of rows in the supplied database table. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Search /keyword:KEYWORD` | Search column names in the supplied table of the database you are connected to. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `Tables /db:DATABASE` | Display all tables in the supplied database. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :negative_squared_cross_mark: |
| `EnableRpc /rhost:LINKED_HOST` | Enable RPC and RPC out on a linked server. | :white_check_mark: | :x: | :x: | :heavy_check_mark: |
| `EnableClr` | Enable CLR integration. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `EnableOle` | Enable OLE automation procedures. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `EnableXp` | Enable xp_cmdshell. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `DisableRpc /rhost:LINKED_HOST` | Disable RPC and RPC out on a linked server. | :white_check_mark: | :x: | :x: | :heavy_check_mark: |
| `DisableClr` | Disable CLR integration. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `DisableOle` | Disable OLE automation procedures. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `DisableXp` | Disable xp_cmdshell. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `AgentStatus` | Display if SQL agent is running and obtain agent jobs. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `AgentCmd /c:COMMAND` | Execute a system command using agent jobs. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `Adsi /adsi:SERVER_NAME /lport:LOCAL_PORT` | Obtain cleartext ADSI credentials from a linked ADSI server. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `Clr /dll:DLL /function:FUNCTION` | Load and execute a .NET assembly in a custom stored procedure. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `OleCmd /c:COMMAND /subsystem:(OPTIONAL)` | Execute a system command using OLE automation procedures. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |
| `XpCmd /c:COMMAND` | Execute a system command using xp_cmdshell. | :white_check_mark: | :white_check_mark: | :white_check_mark: | :heavy_check_mark: |

### SQL Modules - Standard

The host flag (`/h:, host:`) is required and allows one or more SQL servers. If you want to execute a module against multiple SQL servers, separate the hosts with a comma, for example `/h:SQL01,10.10.10.2,SQL03`.

The wiki has details on using each module which supports execution on one or more instance of <a href="https://github.com/skahwah/SQLRecon/wiki/3.-Standard-Modules">SQL Server</a>.

### SQL Modules - Impersonation

Impersonation modules are executed against one or more instances of Microsoft SQL server, under the context of an impersonated SQL user. All impersonation modules have the following minimum requirements:
- An impersonation user must be specified (`/i:, /iuser:`).
- A module which supports impersonation must be specified (`/m:, /module:`).

The wiki has details on using each module which supports execution using <a href="https://github.com/skahwah/SQLRecon/wiki/4.-Impersonation-Modules">Impersonation</a>.

### SQL Modules - Linked

Linked modules are executed on one or more instances of a linked Microsoft SQL server. All linked modules have the following minimum requirements:
- A linked SQL server must be specified (`/l:, /link:`). The link flag allows one or more linked SQL servers. For example, if SQL01 has a link to SQL02, and SQL01 has a link to DB04, you can separate the linked hosts with a comma, and a module will be executed on each linked SQL server, for example `/l:SQL02,DB04`.
- A module which supports linked execution must be specified (`/m:, /module:`). 

The wiki has details on using each module which supports execution on one or more instance of a <a href="https://github.com/skahwah/SQLRecon/wiki/5.-Linked-Modules">Linked SQL Server</a>.

### SQL Modules - Linked Chain

Linked chain modules are executed on the final Microsoft SQL server in a linked server chain. All linked chain modules have the following minimum requirements:
- A linked SQL server chain must be specified in the `/l:, /link:` flag. If SQL01 has a link to SQL02, and SQL02 has a link to PAYMENTS01, and you want to execute a module on PAYMENTS01, then the argument would be `/l:SQL02,PAYMENTS01`.
- The `/chain` flag must be included to execute the module against the final SQL server in the supplied linked chain.
- A module which supports linked chain execution must be specified (`/m:, /module:`).

The wiki has details on using each module which supports execution on the final SQL server supplied in a <a href="https://github.com/skahwah/SQLRecon/wiki/6.-Linked-Chain-Modules">Linked SQL Server Chain</a>.

# SCCM Modules

SQLRecon has several modules that can assist with enumerating and attacking Microsoft System Center Configuration Manager (SCCM) and Microsoft Endpoint Configuration Manager (ECM). The SCCM or ECM server will need to have a Microsoft SQL database exposed either locally or remotely.

SCCM modules must be passed into the SCCM module flag (`/s:, /sccm:`).

Most of the SCCM modules can be executed under the context of an impersonated SQL user (`/i:, /iuser:`).

The wiki has details on using each module against an <a href="https://github.com/skahwah/SQLRecon/wiki/7.-SCCM-Modules">SCCM/ECM database</a>. 


| Module Name | Description | Impersonation | Requires Privileged Context |
| ----------- | ----------- | ------------- | --------------------------- |
| `Users` | Display all SCCM users. | :white_check_mark: | :negative_squared_cross_mark: |
| `Sites` | Display all other sites with data stored. | :white_check_mark: | :negative_squared_cross_mark: |
| `Logons` | Display all associated SCCM clients and the last logged in user. | :white_check_mark: | :negative_squared_cross_mark: |
| `Credentials` | Display encrypted credentials vaulted by SCCM. | :white_check_mark: | :negative_squared_cross_mark: |
| `TaskList` | Display all task sequences, but do not access the task data contents. | :white_check_mark: | :negative_squared_cross_mark: |
| `TaskData` | Decrypt all task sequences to plaintext. | :white_check_mark: | :negative_squared_cross_mark: |
| `DecryptCredentials` | Decrypt an SCCM credential blob. Must execute in a high-integrity or SYSTEM process on the SCCM server. | :x: | :heavy_check_mark: |
| `AddAdmin /user:DOMAIN\USERNAME /sid:SID` | Elevate a supplied account to a 'Full Administrator' in SCCM. | :white_check_mark: | :heavy_check_mark: |
| `RemoveAdmin /user:ADMIN_ID /remove:STRING` | Removes privileges of a user, or remove a user entirely from the SCCM database. | :white_check_mark: | :heavy_check_mark: |


<details>
<summary>SCCM Modules - Additional Details</summary>

* The `Users` module lists all users in the `RBAC_Admins` table. These are all users configured for some level of access to SCCM.
* The `Sites` module lists all other sites with data stored in the SCCM databases' `DPInfo` table. This can provide additional attack avenues as different sites can be configured in different (insecure) ways.
* The `Logons` module queries the `Computer_System_DATA` table to retrieve all associated SCCM clients along with the user that last logged into them. <b>NOTE:</b> This only updates once a week by default and will not be 100% up to date. Use `/option:` as an optional (not required) argument to filter SCCM clients.
* The `TaskList` module provides a list of all task sequences stored in the SCCM database, but does not access the actual task data contents.
* The `TaskData` module recovers all task sequences stored in the SCCM database and decrypts them to plaintext. Task sequences can contain credentials for joining systems to domains, mapping shares, running commands, etc.
* The `Credentials` module lists credentials vaulted by SCCM for use in various functions. These credentials can not be remotely decrypted as the key is stored on the SCCM server. However, this module provides intel on if it makes sense to attempt to obtain the key.
* The `DecryptCredentials` module attempts to decrypt recovered SCCM credential blobs. This module must be ran in a high-integrty or SYSTEM process on an SCCM server.
* The `AddAdmin` module elevates the specified account to a 'Full Administrator' within SCCM. If target user is already an SCCM user, this module will instead add necessary privileges to elevate. Provide two arguments, either `/user:current /sid:current` if seeking to add the user currently executing the SQLRecon process as a 'Full Administrator' in SCCM. If seeking to add another user as a 'Full Administrator' in SCCM, specify their domain user name and full SID `/user:DOMAIN\USERNAME /sid:S-1-5-...`.  This module require sysadmin or similar privileges as writing to SCCM database tables is required.
* The `RemoveAdmin` module removes the privileges of a user by removing a newly added user entirely from the SCCM database. If the user already existed in some capacity this module just removes the three roles that were added to the account via writes to the permission table. Use the arguments provided by output of the `sAddAdmin` command to run this command. This module require sysadmin or similar privileges as writing to SCCM database tables is required.
</details>

# Extending SQLRecon

If you are interested in extending SQLRecon, please refer to the contributing and extending section in the <a href="https://github.com/skahwah/SQLRecon/wiki/8.-Contributing-and-Extending-SQLRecon">wiki</a>.

I encourage you to open an [issue](https://github.com/skahwah/SQLRecon/issues) if you have any suggestions or ideas.

### Roadmap

The goal is to continuously improve SQLRecon. Listed below are some planned research areas:

* Implement support for NTLM hash-based authentication.
* Explore enablerpc/disablerpc functionalities for linked and link chained SQL servers.

### Credits

The following people have contributed either directly or indirectly to various aspects of SQLRecon.

- Adam Chester [(xpn)](https://github.com/xpn)
- Azaël Martin [(n3rada)](https://github.com/n3rada)
- Daniel Duggan [(rasta-mouse)](https://github.com/rasta-mouse)
- Dave Cossa [(G0ldenGunSec)](https://github.com/G0ldenGunSec)
- Dwight Hohnstein [(djhohnstein)](https://github.com/djhohnstein)
- Joshua Magri [(passthehashbrowns)](https://github.com/passthehashbrowns)

# History

<details>
<summary>v3.8</summary>

* Added logic to support the execution of CLR assemblies on SQL Server 2016 and below. This is for the clr module. Execution supported in all contexts.
* Added logic to load a LDAP server CLR assembly on SQL Server 2016 and below. This is for the adsi module. Execution supported in all contexts.
* Updated README.
* Updated Wiki.
</details>

<details>
<summary>v3.7</summary>

* Complete refactor of code base.
* Updated documentation (code comments, README, and wiki)
* Execution against a linked SQL server chain. For example, if `SQL01` has a link to `SQL02`, and `SQL02`, has a link to `SQL03`, and `SQL03`, has a link to `PAYMENTS01`. It is now possible to execute commands from `SQL01` on `PAYMENTS01` using the linked server chain (`/link:SQL02,SQL03,PAYMENTS01 /chain`). Credit to Azaël Martin (n3rada).
* Removed '`l`' and '`i`' modules, and introduced context logic so module names can be the same across standard, impersonation, linked and chained execution.
* Added chain support to all linked modules.
* Added support for debug (`/debug`), which will display various debugging information and all SQL queries that will be executed by a module, without executing them.
* Added verbose (`/verbose, /v`), which will display all SQL queries that will be executed during module execution.
* Added timeout (`/timeout, /t`), which takes an integer value for SQL server database connection timeout.
* Improved `links` module to include detailed information. Credit to Azaël Martin (n3rada). 
* Improved `whoami` module to include Windows principals and database users. Credit to Azaël Martin (n3rada). 
* Improved `impersonation` module to include Windows principals and database users. Credit to Azaël Martin (n3rada).
* Added IP address retrieval into the `sqlspns` enumeration module. Credit to Azaël Martin (n3rada). 
* Standardized console output to markdown where applicable. Credit to Azaël Martin (n3rada). 
* Added DNS support to `/enum:info` module.
* Added optional `/subsystem` argument to the `olecmdexec` module, which accepts execution using the `CmdExec` or `PowerShell` OLE automation subsystems.
* Updated test harnesses to reflect CLI changes and new modules.
* Changed `AzureAD` authentication to `EntraID`.
</details>

<details>
<summary>v3.6</summary>

* Execution against multiple SQL servers supplied in the `/host` or `/h` flag is now supported using comma separated values.
* Execution against multiple linked SQL servers supplied in the `/link` or `/l` flag is now supported using comma separated values.
* Changed `/lhost` to `/link`.
* Removed '`s`' modules and created the `/s`, `/sccm` switch for SCCM modules.
* Added impersonation support to all SCCM modules, with the exception of `DecryptCredentials`.
* Added a new enumeration (`/enum`) module called `info` which is able to used an unauthenticated context to obtain SQL server information, including instance name and TCP port using the UDP protocol.
* Moved argument logic into individual methods within `ModuleHandler.cs` to promote simplification and extensibility.
* Moved all SQL queries to `Queries.cs`.
* Created `EnumerationModules.cs`.
* Created `FormatQuery.cs`.
* Created `SccmModules.cs`.
* Renamed `ModuleHandler.cs` to `SqlModules.cs`.
</details>

<details>
<summary>v3.5</summary>

* Bug fix where linked `adsi` execution was not removing the LDAP server.
* Removed agent job execution from linked `adsi`, in favor of openquery/rpc.
* Changed `/lhost` to `/adsi` in in `adsi` module.
* Changed `/rhost` to `/unc` in `smb` module.
* Removed `CaptureHash.cs` and simplified logic.
* Removed `SetEnumerationType.cs` and simplified logic.
* Renamed `Impersonation.cs` to `Impersonate.cs`.
* Renamed `OleCmdExec.cs` to `OleAutomation.cs`.
* Renamed `PrintUtils.cs` to `Print.cs`.
* Renamed `SQLServerInfo.cs` to `Info.cs`.
</details>

<details>
<summary>v3.4</summary>

* Added impersonation support for `smb` module.
* Added impersonation support for `info` module.
* Added linked support for `info` module.
</details>

<details>
<summary>v3.3</summary>

* Created `rows`, `iRows` and `lRows` modules.
* Updated `sLogons` to include an optional filter.
* Bug fix where `xp_cmdshell` modules were not printing command output to console.
* Cleaned up Help menu.
</details>

<details>
<summary>v3.2</summary>

* Command line argument parsing overhaul.
* Updated README, test cases and wiki with new examples.
* Reworked enumeration and authentication based argument parsing.
* Created `SetEnumerationType.cs`.
* Changed enumeration module `domain` to `SqlSpns`.
</details>

<details>
<summary>v3.1</summary>

* Changed `SetAuthenticationType.cs` constructor to a new method called `EvaluateAuthenticationType`.
* Created `CreateSqlConnectionObject` in `SetAuthenticationType.cs` which extends SQLRecon to support multiple simultaneous SQL connection objects.
* Created `ADSI.cs`, which incorporates ADSI credential attacks as described [here](https://www.tarlogic.com/blog/linked-servers-adsi-passwords/).
* Created `adsi`, `iAdsi`, and `lAdsi` modules.
* Created `lLinks` and `iLinks` modules.
* Updated README, test cases and wiki with new examples.
</details>

<details>
<summary>v3.0</summary>

* Implemented error checking for non-existant impersonated users.
* Created `ExecuteImpersonationQuery` and `ExecuteImpersonationCustomQuery`.
* Deleted `Impersonate.cs`
* Added `checkRpc` module.
* Added `iCheckRpc` module.
* Added `lCheckRpc` module.
* Reworked SCCM modules.
* Reworked SCCM argument parsing.
* Camel cased commands in help menu for easier reading.
* Updated tests with new modules.
</details>

<details>
<summary>v2.9</summary>

* Renamed `EnableDisable.cs` to `ConfigureOptions.cs`
* Overhauled advanced option configurations.
* Implemented RPC error checking wherever `ExecuteLinkedCustomQueryRpcExec` is called.
</details>

<details>
<summary>v2.8</summary>

* Created` PrintUtils.cs`, which implements a print class for standardized output.
* Moved `TablePrinter` from `Help.cs` to `PrintUtils.cs`.
* Standardized print formatting for all console output using the `PrintUtils` class.
* Changed access modifiers for classes and class variables.
* Added check to see if result is empty for: 
    * `query`
    * `search`
    * `tables`
    * `lColumns`
    * `lQuery`
    * `lSearch`
    * `lTables`
    * `iColumns`
    * `iQuery`
    * `iSearch`
* Signifiant reliability and functionality testing against all authentication providers and modules.
</details>

<details>
<summary>v2.7</summary>

* Changed `Azure` authentication to `AzureAD`.
* Created `AzureLocal` authentication.
* Added `disableRpc` module.
* Added `enableRpc` module.
* Added `iEnableRpc` module.
* Added `iDisableRpc` module.
* Removed `lEnableRpc` module.
* Removed `lDisbleRpc` module.
* Updated tests with new modules.
</details>

<details>
<summary>v2.6.1</summary>

* `lAgentCmd` bug fixes.
* Fixed `clr`, `iClr` and `lClr` stability by using `SqlCommand.ExecuteNonQuery` when creating the stored procedure.
* Fixed `lClr` bug where it was not removing created assemblies or stored procedures.
</details>

<details>
<summary>v2.6</summary>

* Added `columns` module.
* Added `iColumns` module.
* Added `iDatabases` module.
* Added `iSearch` module.
* Added `iTables` module.
* Added `lColumns` module.
* Added `lSearch` module.
</details>

<details>
<summary>v2.5</summary>

* Various bug fixed in the SCCM modules.
* Organized the help menu using a table.
* Improved the output provided by `ExecuteLinkedCustomQueryRpcExec`.
* Improved code commenting through out.
* Improved consistency of method names across command execution functions.
* Improved modularity through better use of object oriented programming.
* Changed custom SQL server port flag to `x`.
* Moved `Random.cs` into `utilities` directory.
* Standardized the printing style to make it more consistent across all modules.
* Created standard, impersonation and linked test harnesses.
</details>

<details>
<summary>v2.4</summary>

* Changed `Windows` authentication to `WinToken`.
* Created `WinDomain` authentication, which uses AD domain username and password for authentication via impersonation. Check out `Impersonation.cs`.
* Reworked argument parsing and handling across `ArgumentLogic.cs`,` SQLAuthentication.cs` and `ModuleHandler.cs`.
* `ModuleHandler.cs` no longer uses a massive if/else if/else statement to execute modules. Instead, reflection is now used to call methods matching command modules names.
* Added `commands` directory, which has global variables that are used throughout the program.
* Rolled all authentication providers into `SQLAuthentication.cs`.
* Moved argument parsing from `Program.cs` to `ArgumentLogic.cs`.
* Removed the `authentication` directory.
* Changed code style to better follow [Microsoft's C#/.NET style code style guide](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions).
* Changed `Help.cs` from a method into a constructor.
* Changed `CaptureHash.cs` from a method into a constructor.
* Changed `Impersonate.cs` from a method into a constructor.
* Re-factored complete code base.
</details>

<details>
<summary>v2.3</summary>

* Added SCCM functionality.
* Added SCCM modules, which can be executed using the `sccm` command.
* Fixed checking RPC status on linked SQL servers.
* Added the capability to download .NET assemblies via HTTP/S.
</details>

<details>
<summary>v2.2</summary>

* Expanded roles which are queried in the `roles`, `iRoles` and `lRoles` modules.
* Created `users`, `iUsers` and `lUsers` modules.
* Fixed hash not being dropped from `sp_drop_trusted_assembly` in `clr` and `iClr` modules.
* Created `lAgentCmd` module.
* Created `lClr` module.
</details>

<details>
<summary>v2.1.6</summary>

* Added `info` module.
* Corrections in help menu.
* Resolved issues with mandatory arguments with `Local` and `Azure` authentication.
</details>

<details>
<summary>v2.1.5</summary>

* Added module to enumerate domain SPNs (`-e domain`).
</details>

<details>
<summary>v2.1.4</summary>

* Fixed minor string formatting issue.
</details>

<details>
<summary>v2.1.3</summary>

* Added `-r` flag into `Windows` and `Local` authentication modes so that non-standard TCP ports can be supplied.
</details>

<details>
<summary>v2.1.2</summary>

* Improved logic around null connection strings.
</details>

<details>
<summary>v2.1.1</summary>

* Removed `Environment.Exit` from `TestAuthentication.cs`.
</details>

<details>
<summary>v2.1</summary>

* Created `AgentJobs.cs`.
* Created `agentStatus`.
* Created `iAgentStatus`.
* Created `lAgentStatus`.
* Created `agentCmd`.
* Created `iAgentCmd`.
</details>

<details>
<summary>v2.0</summary>

* Created `clr`.
* Created `iEnableClr`.
* Created `iDisbleClr`.
* Created `iClr`.
* Created `iWhoami`.
* Created `iMapped`.
* Created `iRoles`.
* Created `lEnableRpc`.
* Created `lDisableRpc`.
* Created `lWhoai`.
* Created `lEnableXp`.
* Created `lDisableXp`.
* Created `lEnableOle`.
* Created `lDisableOle`.
* Created `lEnableClr`.
* Created `lDisableClr`.
* Created `lXpCmd`.
* Created `lXpOle`.
* Created `Random.cs`.
* Created `EnableDisable.cs`.
* Implemented randomly generated assembly names for `clr`.
* Implemented randomly generated variable and method names for `ole`.
* Rolled `mapped` and `roles` modules into `whoami`.
* Rolled `lMapped` and `lRoles` modules into `lWhoami`.
* Rolled `iMapped` and `iRoles` modules into `iWhoami`.
* Re-factored complete code base.
</details>

<details>
<summary>v1.2</summary>

* Created `lSmb` module.
* Created `lWhoami` module.
* Created `lRoles` module.
</details>

<details>
<summary>v1.1</summary>

* Fixed `oldCmd` module.
* Fixed `iOleCmd` module.
* Fixed `lDatabases` module.
* Fixed `lTables` module.
* Cleaned up code base.
* Corrected inconsistencies in help menu.
</details>
