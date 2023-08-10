using System;
using System.Data.SqlClient;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class SqlServerInfo
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

        private static readonly PrintUtils _print = new();
        private SqlConnection _connection;
        private static readonly SqlQuery _sqlQuery = new();

        public SqlServerInfo(SqlConnection connection)
        {
            _connection = connection;
        }

        /// <summary>
        /// The GetAllSQLServerInfo method will connect to a SQL server
        /// and obtain information about the local SQL server instance.
        /// </summary>
        public void GetAllSQLServerInfo()
        {
            var roles = new Roles();
            var sysadmin = roles.CheckServerRole(_connection, "sysadmin");

            IsSysAdmin = sysadmin ? "Yes" : "No";

            ComputerName = _getComputerName();
            DomainName = _getDomainName();
            ServicePid = _getServicePid();

            if (sysadmin)
            {
                OsMachineType = _getOsMachineType();
                OsVersion = _getOsVersion();
            }

            ServiceName = _getSqlServerServiceName();
            ServiceAccount = _getSqlServiceAccountName();
            AuthenticationMode = _getAuthenticationMode();
            ForcedEncryption = _getForcedEncryption();
            Clustered = _getClustered();
            SqlServerVersionNumber = _getSqlVersionNumber();
            SqlServerMajorVersion = _getSqlMajorVersionNumber();
            SqlServerEdition = _getSqlServerEdition();
            SqlServerServicePack = _getSqlServerServicePack();
            OsArchitecture = _getOsArchitecture();
            OsVersionNumber = _getOsVersionNumber();
            CurrentLogin = _getCurrentLogon();
            ActiveSessions = _getActiveSessions();
        }


        /// <summary>
        /// The PrintInfo method prints objects asssocated with a computer.
        /// </summary>
        public void PrintInfo()
        {
            Console.WriteLine();
            _print.Nested(string.Format("ComputerName:           {0}", ComputerName), true);
            _print.Nested(string.Format("DomainName:             {0}", DomainName), true);
            _print.Nested(string.Format("ServicePid:             {0}", ServicePid), true);
            _print.Nested(string.Format("ServiceName:            {0}", ServiceName), true);
            _print.Nested(string.Format("ServiceAccount:         {0}", ServiceAccount), true);
            _print.Nested(string.Format("AuthenticationMode:     {0}", AuthenticationMode), true);
            _print.Nested(string.Format("ForcedEncryption:       {0}", ForcedEncryption), true);
            _print.Nested(string.Format("Clustered:              {0}", Clustered), true);
            _print.Nested(string.Format("SqlServerVersionNumber: {0}", SqlServerVersionNumber), true);
            _print.Nested(string.Format("SqlServerMajorVersion:  {0}", SqlServerMajorVersion), true);
            _print.Nested(string.Format("SqlServerEdition:       {0}", SqlServerEdition), true);
            _print.Nested(string.Format("SqlServerServicePack:   {0}", SqlServerServicePack), true);
            _print.Nested(string.Format("OsArchitecture:         {0}", OsArchitecture), true);

            if (!string.IsNullOrEmpty(OsMachineType))
                _print.Nested(string.Format("OsMachineType:          {0}", OsMachineType), true);

            if (!string.IsNullOrEmpty(OsVersion))
                _print.Nested(string.Format("OsVersion:              {0}", OsVersion), true);

            _print.Nested(string.Format("OsVersionNumber:        {0}", OsVersionNumber), true);
            _print.Nested(string.Format("CurrentLogin:           {0}", CurrentLogin), true);
            _print.Nested(string.Format("IsSysAdmin:             {0}", IsSysAdmin), true);
            _print.Nested(string.Format("ActiveSessions:         {0}", ActiveSessions), true);
        }

        /// <summary>
        /// The _getComputerName method will get the computer name
        /// from a SQL server.
        /// </summary>
        private string _getComputerName()
        {
            return _sqlQuery.ExecuteQuery(_connection, "SELECT @@SERVERNAME;").TrimStart('\n');
        }

        /// <summary>
        /// The _getDomainName method will get the domain name
        /// from a SQL server.
        /// </summary>
        private string _getDomainName()
        {
            return _sqlQuery.ExecuteQuery(_connection, "SELECT DEFAULT_DOMAIN();").TrimStart('\n');
        }

        /// <summary>
        /// The _getServicePid method will get the service pid
        /// from a SQL server.
        /// </summary>
        private string _getServicePid()
        {
            return _sqlQuery.ExecuteQuery(_connection, "SELECT SERVERPROPERTY('processid');").TrimStart('\n');
        }

        /// <summary>
        /// The _getOsVersion method will get the OS version
        /// from a SQL server.
        /// </summary>
        private string _getOsVersion()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"DECLARE @ProductName  SYSNAME
            EXECUTE master.dbo.xp_regread
            @rootkey		= N'HKEY_LOCAL_MACHINE',
            @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
            @value_name		= N'ProductName',
            @value			= @ProductName output
            SELECT @ProductName;").TrimStart('\n');
        }

        /// <summary>
        /// The _getSqlServerServiceName method will get the SQL service name
        /// from a SQL server.
        /// </summary>
        private string _getSqlServerServiceName()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"DECLARE @SQLServerServiceName varchar(250)
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

        /// <summary>
        /// The _getSqlServiceAccountName method will get the SQL service account name
        /// from a SQL server.
        /// </summary>
        private string _getSqlServiceAccountName()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"DECLARE @SQLServerInstance varchar(250)
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

        /// <summary>
        /// The _getAuthenticationMode method will get the authentication mode
        /// from a SQL server.
        /// </summary>
        private string _getAuthenticationMode()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END);").TrimStart('\n');
        }

        /// <summary>
        /// The _getForcedEncryption method will get the encryption mode
        /// from a SQL server.
        /// </summary>
        private string _getForcedEncryption()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"BEGIN TRY 
            DECLARE @ForcedEncryption INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
            N'ForceEncryption', @ForcedEncryption OUTPUT
            END TRY
            BEGIN CATCH	            
            END CATCH
            SELECT @ForcedEncryption;").TrimStart('\n');
        }

        /// <summary>
        /// The _getClustered method will get the cluster method
        /// from a SQL server.
        /// </summary>
        private string _getClustered()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END").TrimStart('\n');
        }

        /// <summary>
        /// The _getSqlVersionNumber method will get the SQL version number
        /// from a SQL server.
        /// </summary>
        private string _getSqlVersionNumber()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT SERVERPROPERTY('productversion');").TrimStart('\n');
        }

        /// <summary>
        /// The _getSqlMajorVersionNumber method will get the SQL version major number
        /// from a SQL server.
        /// </summary>
        private string _getSqlMajorVersionNumber()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4);").TrimStart('\n');
        }

        /// <summary>
        /// The _getSqlServerEdition method will get the SQL edition
        /// from a SQL server.
        /// </summary>
        private string _getSqlServerEdition()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT SERVERPROPERTY('Edition');").TrimStart('\n');
        }

        /// <summary>
        /// The _getSqlServerServicePack method will get the SQL service pack version
        /// from a SQL server.
        /// </summary>
        private string _getSqlServerServicePack()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT SERVERPROPERTY('ProductLevel');").TrimStart('\n');
        }

        /// <summary>
        /// The _getOsMachineType method will get the OS type
        /// from a SQL server.
        /// </summary>
        private string _getOsMachineType()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"DECLARE @MachineType  SYSNAME
            EXECUTE master.dbo.xp_regread
            @rootkey		= N'HKEY_LOCAL_MACHINE',
            @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
            @value_name		= N'ProductType',
            @value			= @MachineType output
            SELECT @MachineType;").TrimStart('\n');
        }

        /// <summary>
        /// The _getOsArchitecture method will get the OS architecture
        /// from a SQL server.
        /// </summary>
        private string _getOsArchitecture()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3);").TrimStart('\n');
        }

        /// <summary>
        /// The _getOsVersionNumber method will get the OS version number
        /// from a SQL server.
        /// </summary>
        private string _getOsVersionNumber()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows Server', @@VERSION), 19), 4);").TrimStart('\n');
        }

        /// <summary>
        /// The _getCurrentLogon method will get the currently logged on user
        /// from a SQL server.
        /// </summary>
        private string _getCurrentLogon()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT SYSTEM_USER;").TrimStart('\n');
        }

        /// <summary>
        /// The _getActiveSessions method will get the active logon sessions
        /// from a SQL server.
        /// </summary>
        private string _getActiveSessions()
        {
            return _sqlQuery.ExecuteQuery(_connection, @"SELECT COUNT(*) FROM [sys].[dm_exec_sessions] WHERE status = 'running';").TrimStart('\n');
        }
    }
}