using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{

    public class SQLServerInfo
    {
        public string ComputerName { get; set; }
        public string DomainName { get; set; }
        public string ServicePid { get; set; }
        public string ServiceName { get; set; }
        public string ServiceAccount { get; set; }
        public string AuthenticationMode { get; set; }
        public string ForcedEncryption { get; set; }
        public string Clustered { get; set; }
        public string SqlServerVersionNumber { get; set; }
        public string SqlServerMajorVersion { get; set; }
        public string SqlServerEdition { get; set; }
        public string SqlServerServicePack { get; set; }
        public string OsArchitecture { get; set; }
        public string OsMachineType { get; set; }
        public string OsVersion { get; set; }
        public string OsVersionNumber { get; set; }
        public string CurrentLogin { get; set; }
        public string IsSysAdmin { get; set; }
        public string ActiveSessions { get; set; }

        private readonly SqlConnection _connection;

        public SQLServerInfo(SqlConnection connection)
        {
            _connection = connection;
        }

        public void GetAllSQLServerInfo()
        {
            var roles = new Roles();
            var sysadmin = roles.CheckServerRole(_connection, "sysadmin");

            IsSysAdmin = sysadmin ? "Yes" : "No";

            ComputerName = GetComputerName();
            DomainName = GetDomainName();
            ServicePid = GetServicePid();

            if (sysadmin)
            {
                OsMachineType = GetOsMachineType();
                OsVersion = GetOsVersion();
            }

            ServiceName = GetSqlServerServiceName();
            ServiceAccount = GetSqlServiceAccountName();
            AuthenticationMode = GetAuthenticationMode();
            ForcedEncryption = GetForcedEncryption();
            Clustered = GetClustered();
            SqlServerVersionNumber = GetSqlVersionNumber();
            SqlServerMajorVersion = GetSqlMajorVersionNumber();
            SqlServerEdition = GetSqlServerEdition();
            SqlServerServicePack = GetSqlServerServicePack();
            OsArchitecture = GetOsArchitecture();
            OsVersionNumber = GetOsVersionNumber();
            CurrentLogin = GetCurrentLogon();
            ActiveSessions = GetActiveSessions();
        }

        public void PrintInfo()
        {
            Console.WriteLine();
            Console.WriteLine("ComputerName:           {0}", ComputerName);
            Console.WriteLine("DomainName:             {0}", DomainName);
            Console.WriteLine("ServicePid:             {0}", ServicePid);
            Console.WriteLine("ServiceName:            {0}", ServiceName);
            Console.WriteLine("ServiceAccount:         {0}", ServiceAccount);
            Console.WriteLine("AuthenticationMode:     {0}", AuthenticationMode);
            Console.WriteLine("ForcedEncryption:       {0}", ForcedEncryption);
            Console.WriteLine("Clustered:              {0}", Clustered);
            Console.WriteLine("SqlServerVersionNumber: {0}", SqlServerVersionNumber);
            Console.WriteLine("SqlServerMajorVersion:  {0}", SqlServerMajorVersion);
            Console.WriteLine("SqlServerEdition:       {0}", SqlServerEdition);
            Console.WriteLine("SqlServerServicePack:   {0}", SqlServerServicePack);
            Console.WriteLine("OsArchitecture:         {0}", OsArchitecture);

            if (!string.IsNullOrEmpty(OsMachineType))
                Console.WriteLine("OsMachineType:          {0}", OsMachineType);

            if (!string.IsNullOrEmpty(OsVersion))
                Console.WriteLine("OsVersion:              {0}", OsVersion);

            Console.WriteLine("OsVersionNumber:        {0}", OsVersionNumber);
            Console.WriteLine("CurrentLogin:           {0}", CurrentLogin);
            Console.WriteLine("IsSysAdmin:             {0}", IsSysAdmin);
            Console.WriteLine("ActiveSessions:         {0}", ActiveSessions);
        }

        public string GetComputerName()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, "SELECT @@SERVERNAME;").TrimStart('\n');
        }

        public string GetDomainName()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, "SELECT DEFAULT_DOMAIN();").TrimStart('\n');
        }

        public string GetServicePid()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, "SELECT SERVERPROPERTY('processid');").TrimStart('\n');
        }

        public string GetOsVersion()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"DECLARE @ProductName  SYSNAME
            EXECUTE master.dbo.xp_regread
            @rootkey		= N'HKEY_LOCAL_MACHINE',
            @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
            @value_name		= N'ProductName',
            @value			= @ProductName output
            SELECT @ProductName;").TrimStart('\n');
        }

        public string GetSqlServerServiceName()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"DECLARE @SQLServerServiceName varchar(250)
            DECLARE @SQLServerInstance varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @SQLServerServiceName = 'MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END
            SELECT @SQLServerServiceName;").TrimStart('\n');
        }

        public string GetSqlServiceAccountName()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"DECLARE @SQLServerInstance varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END

            DECLARE @ServiceAccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'
            SELECT @ServiceAccountName;").TrimStart('\n');
        }

        public string GetAuthenticationMode()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END);").TrimStart('\n');
        }

        public string GetForcedEncryption()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"BEGIN TRY 
            DECLARE @ForcedEncryption INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
            N'ForceEncryption', @ForcedEncryption OUTPUT
            END TRY
            BEGIN CATCH	            
            END CATCH
            SELECT @ForcedEncryption;").TrimStart('\n');
        }

        public string GetClustered()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END").TrimStart('\n');
        }

        public string GetSqlVersionNumber()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT SERVERPROPERTY('productversion');").TrimStart('\n');
        }

        public string GetSqlMajorVersionNumber()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4);").TrimStart('\n');
        }

        public string GetSqlServerEdition()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT SERVERPROPERTY('Edition');").TrimStart('\n');
        }

        public string GetSqlServerServicePack()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT SERVERPROPERTY('ProductLevel');").TrimStart('\n');
        }

        public string GetOsMachineType()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"DECLARE @MachineType  SYSNAME
            EXECUTE master.dbo.xp_regread
            @rootkey		= N'HKEY_LOCAL_MACHINE',
            @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
            @value_name		= N'ProductType',
            @value			= @MachineType output
            SELECT @MachineType;").TrimStart('\n');
        }

        public string GetOsArchitecture()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3);").TrimStart('\n');
        }

        public string GetOsVersionNumber()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows Server', @@VERSION), 19), 4);").TrimStart('\n');
        }

        public string GetCurrentLogon()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT SYSTEM_USER;").TrimStart('\n');
        }

        public string GetActiveSessions()
        {
            var query = new SQLQuery();
            return query.ExecuteQuery(_connection, @"SELECT COUNT(*) FROM [sys].[dm_exec_sessions] WHERE status = 'running';").TrimStart('\n');
        }
    }
}