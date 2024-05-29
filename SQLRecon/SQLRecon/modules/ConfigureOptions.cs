using System;
using System.Data.SqlClient;
using System.Linq;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class Configure
    {
        private static readonly PrintUtils _print = new();
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The ModuleStatus method checks if advanced options are enabled
        /// for the clr, ole or xp_cmdshell modules via sp_configure. Logic
        /// also exists to check if rpc has been enabled, cross checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <param name="sqlServer">optional</param>
        /// <returns></returns>
        public string ModuleStatus(SqlConnection con, string module, string impersonate = "null", string sqlServer = "null")
        {
            if (impersonate.Equals("null"))
            {
                if (module.Equals("rpc"))
                {
                    // Obtain all SQL server names where RPC is enabled.
                    // Returns 1 for enabled if the supplied sqlServer exists.
                    // Returns 0 for disabled if the supplied sqlServer does not exist.
                    string result = _sqlQuery.ExecuteCustomQuery(con,
                    "SELECT is_rpc_out_enabled FROM sys.servers WHERE lower(name) like '%" + sqlServer.ToLower() + "%';");

                    return (result.Contains("True"))
                        ? "1"
                        : "0";
                }
                else
                {
                    // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                    // is either a 1 (enabled) or 0 (disabled). Return the value.
                    return _sqlQuery.ExecuteQuery(con, "EXEC sp_configure 'show advanced options', 1; " +
                    "SELECT value FROM sys.configurations WHERE name = '" + module + "';");
                }
            }
            else
            {
                if (module.Equals("rpc"))
                {
                    // Obtain all SQL server names where RPC is enabled.
                    // Returns 1 for enabled if the supplied sqlServer exists.
                    // Returns 0 for disabled if the supplied sqlServer does not exist.
                    string result = _sqlQuery.ExecuteCustomQuery(con,
                    "SELECT is_rpc_out_enabled FROM sys.servers WHERE lower(name) like '%" + sqlServer.ToLower() + "%';");

                    return (result.Contains("True"))
                        ? "1"
                        : "0";
                }
                else
                {
                    // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                    // is either a 1 (enabled) or 0 (disabled). Return the value.
                    return _sqlQuery.ExecuteQuery(con,
                    "SELECT value FROM sys.configurations WHERE name = '" + module + "';");
                }
            }
        }

        /// <summary>
        /// The LinkedModuleStatus method checks if advanced options are enabled
        /// for modules via sp_configure on a linked SQL server. Logic
        /// also exists to check if rpc has been enabled, cross checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="linkedSqlServer"></param>
        /// <returns></returns>
        public string LinkedModuleStatus(SqlConnection con, string module, string linkedSqlServer)
        {
                // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                // is either a 1 (enabled) or 0 (disabled). Return the value.
                return _sqlQuery.ExecuteTunnelQuery(con, linkedSqlServer,
                "SELECT value FROM sys.configurations WHERE name = ''" + module + "'';");
        }

        /// <summary>
        /// The ModuleToggle method will enable advanced options, then
        /// enable modules via sp_configure. Logic exists for impersonation. Logic exists for rpc.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module">Common modules include: clr enabled,
        /// ole automation procedures, and xp_cmdshell. Special logic has been included for rpc.</param>
        /// <param name="value">Enable (1) or disable (0).</param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate"></param>
        public void ModuleToggle(SqlConnection con, string module, string value, string sqlServer, string impersonate = "null")
        {
            try
            {
                string sqlOutput;

                if (module.Equals("rpc"))
                {
                    _sqlQuery.ExecuteCustomQuery(con, "EXEC sp_serveroption '" + sqlServer + "', 'rpc out', '" + value + "';");

                    // Convert value from true to 1, and
                    // from false to 0 for the _moduleStatus method.
                    value = (value.Equals("true"))
                        ? "1"
                        : "0";

                    sqlOutput = ModuleStatus(con, module, "null", sqlServer);
                    _printModuleStatus(sqlOutput, module, value, sqlServer);

                    sqlOutput = _moduleStatus(con, module, "null", sqlServer);
                    if (!sqlOutput.ToLower().Contains("not have permission")){
                        Console.WriteLine(sqlOutput);
                        return;
                    }
                }
                else
                {
                    _sqlQuery.ExecuteQuery(con, $"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '{module}', {value}; RECONFIGURE;");

                    sqlOutput = ModuleStatus(con, module);
                    _printModuleStatus(sqlOutput, module, value, sqlServer);

                    sqlOutput = _moduleStatus(con, module, impersonate, sqlServer);
                    if (!sqlOutput.ToLower().Contains("not have permission")){
                        Console.WriteLine(sqlOutput);
                        return ;
                    }

                }
                return;
            }
            catch (Exception ex)
            {
                _print.Error($"Error enabling module {module}: {ex.Message}", true);
                return;
            }
        }

        /// <summary>
        /// The LinkedModuleToggle method will enable advanced options, then
        /// enable modules via sp_configure.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module">Common modules include: clr enabled,
        /// ole automation procedures, and xp_cmdshell.</param>
        /// <param name="value">Enable (1) or disable (0).</param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="sqlServer"></param>
        public void LinkedModuleToggle(SqlConnection con, string module, string value, string linkedSqlServer, string sqlServer)
        {
            try
            {
                // First check to see if rpc is enabled.
                string sqlOutput = ModuleStatus(con, "rpc", "null", linkedSqlServer);

                if (!sqlOutput.Contains("1"))
                {
                    _print.Error(string.Format("You need to enable RPC for {0} on {1} (enablerpc -o {0}).",
                        linkedSqlServer, sqlServer), true);
                    Console.WriteLine(_moduleStatus(con, "rpc", "null", linkedSqlServer));
                    return;
                }

                _sqlQuery.ExecuteTunnelCustomQueryRpcExec(con, linkedSqlServer, $"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '{module}', {value}; RECONFIGURE;");
                sqlOutput = LinkedModuleStatus(con, module, linkedSqlServer);

                _printModuleStatus(sqlOutput, module, value, linkedSqlServer);

                sqlOutput = _linkedModuleStatus(con, module, linkedSqlServer);
                if (!sqlOutput.ToLower().Contains("not have permission"))
                {
                    Console.WriteLine(sqlOutput);
                    return;
                }

                return;
            }
            catch (Exception ex)
            {
                _print.Error($"Error enabling module {module} on linked server: {ex.Message}", true);
                return;
            }
        }

        /// <summary>
        /// The TunnelModuleToggle method will enable advanced options, then
        /// enable modules via sp_configure on a chain of linked SQL servers.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module">Common modules include: clr enabled, ole automation procedures, and xp_cmdshell.</param>
        /// <param name="value">Enable (1) or disable (0).</param>
        /// <param name="tunnelSqlServers">An array of server names representing the tunnel path.</param>
        /// <param name="sqlServer">The initial SQL server.</param>
        public void TunnelModuleToggle(SqlConnection con, string module, string value, string[] tunnelSqlServers, string sqlServer)
        {
            try
            {
                // Enable advanced options and the specified module on the last server in the tunnel.
                _sqlQuery.ExecuteTunnelCustomQueryRpcExec(con, tunnelSqlServers, $"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '{module}', {value}; RECONFIGURE;");

                string sqlOutput = TunnelModuleStatus(con, module, tunnelSqlServers);

                _printModuleStatus(sqlOutput, module, value, tunnelSqlServers.Last());

                sqlOutput = TunnelModuleStatus(con, module, tunnelSqlServers);
                if (!sqlOutput.ToLower().Contains("not have permission"))
                {
                    Console.WriteLine(sqlOutput);
                    return;
                }

                return;
            }
            catch (Exception ex)
            {
                _print.Error($"Error enabling module {module} on tunnel: {ex.Message}", true);
                return;
            }
        }

        /// <summary>
        /// The _moduleStatus method checks if advanced options are enabled
        /// for the clr, ole or xp_cmdshell modules via sp_configure. Logic
        /// also exists to check if rpc has been enabled, cross checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <param name="sqlServer">Optional</param>
        /// <returns></returns>
        private string _moduleStatus(SqlConnection con, string module, string impersonate = "null", string sqlServer = "null")
        {
            if (impersonate.Equals("null"))
            {
                if (module.Equals("rpc"))
                {
                    // Obtain all SQL server names where RPC is enabled if the name matches supplied SQL server.
                    return _sqlQuery.ExecuteCustomQuery(con,
                    "SELECT name, is_rpc_out_enabled FROM sys.servers WHERE lower(name) like '%" + sqlServer.ToLower() + "%';");

                }
                else
                {
                    // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                    // Return the name and value.
                    return _sqlQuery.ExecuteCustomQuery(con, "EXEC sp_configure 'show advanced options', 1; " +
                    "SELECT name, value FROM sys.configurations WHERE name = '" + module + "';");
                }
            }
            else
            {
                if (module.Equals("rpc"))
                {
                    // Obtain all SQL server names where RPC is enabled.
                    // Returns 1 for enabled if the supplied sqlServer exists.
                    // Returns 0 for disabled if the supplied sqlServer does not exist.
                    return _sqlQuery.ExecuteCustomQuery(con,
                    "SELECT name, is_rpc_out_enabled FROM sys.servers WHERE lower(name) like '%" + sqlServer.ToLower() + "%';");
                }
                else
                {
                    // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                    // is either a 1 (enabled) or 2 (disabled). Return the value.
                    return _sqlQuery.ExecuteCustomQuery(con,
                    "SELECT name, value FROM sys.configurations WHERE name = '" + module + "';");
                }
            }
        }

        /// <summary>
        /// The _linkedModuleStatus method checks if advanced options are enabled
        /// for modules via sp_configure on a linked SQL server. Logic
        /// also exists to check if rpc has been enabled, cross checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="linkedSqlServer"></param>
        /// <returns></returns>
        private string _linkedModuleStatus(SqlConnection con, string module, string linkedSqlServer)
        {
            // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
            // is either a 1 (enabled) or 2 (disabled). Return the name and value.
            return _sqlQuery.ExecuteTunnelCustomQuery(con, linkedSqlServer,
            "SELECT name, value FROM sys.configurations WHERE name = ''" + module + "'';");
        }


        /// <summary>
        /// The TunnelModuleStatus method checks if advanced options are enabled
        /// for modules via sp_configure on a chain of linked SQL servers.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="tunnelSqlServers"></param>
        /// <returns></returns>
        public string TunnelModuleStatus(SqlConnection con, string module, string[] tunnelSqlServers)
        {
            // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
            // is either a 1 (enabled) or 2 (disabled). Return the name and value.
            return _sqlQuery.ExecuteTunnelCustomQuery(con, tunnelSqlServers,
            $"SELECT name, value FROM sys.configurations WHERE name = '{module}';");
        }


        /// <summary>
        /// The _printModuleStatus method validates if a module has been enabled
        /// or disabled.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="value">Enable (1) or disable (0).</param>
        /// <param name="module">Common modules include: clr enabled,
        /// ole automation procedures, and xp_cmdshell.</param>
        /// <param name="sqlServer"></param>
        private void _printModuleStatus(string sqlOutput, string module, string value, string sqlServer)
        {
            // Change the format of the string
            if (module.Equals("clr enabled"))
                module = "CLR";

            if (sqlOutput.Contains("0") && value.Equals("0"))
            {
                _print.Success(string.Format("Disabled {0} on {1}.", module, sqlServer), true);
            }
            else if (sqlOutput.Contains("1") && value.Equals("1"))
            {
                _print.Success(string.Format("Enabled {0} on {1}.", module, sqlServer), true);
            }
            else if (sqlOutput.Contains("0") && value.Equals("1"))
            {
                _print.Error(string.Format("The current user does not " +
                    "have permissions to enable or disable {0} on {1}.", module, sqlServer), true);
            }
            else if (sqlOutput.Contains("1") && value.Equals("0"))
            {
                _print.Error(string.Format("The current user does not " +
                    "have permissions to enable or disable {0} on {1}.", module, sqlServer), true);
            }
            else
            {
                Console.WriteLine(sqlOutput);
            }
        }
    }
}
