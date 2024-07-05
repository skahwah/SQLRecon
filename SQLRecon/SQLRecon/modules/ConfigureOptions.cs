using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Config
    {
        /// <summary>
        /// The ModuleStatus method checks if advanced options are enabled
        /// for the clr, ole or xp_cmdshell modules via sp_configure. Logic
        /// also exists to check if rpc has been enabled, cross-checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <param name="sqlServer">optional</param>
        /// <returns></returns>
        internal static bool ModuleStatus(SqlConnection con, string module, string impersonate = null, string sqlServer = "")
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                {"get_rpc_status", string.Format(Query.GetRpcStatus, sqlServer.ToLower())},
                {"enable_advanced_options", Query.EnableAdvancedOptions},
                {"get_module_status", string.Format(Query.GetModuleStatus, module)}
            };

            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }

            if (module.Equals("rpc"))
            {
                // Obtain all SQL server names where RPC is enabled.
                // Returns 1 for enabled if the supplied sqlServer exists.
                // Returns 0 for disabled if the supplied sqlServer does not exist.
                return Sql.CustomQuery(con, queries["get_rpc_status"]).ToLower().Contains("true");
            }
            else
            {
                // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                // is either a 1 (enabled) or 0 (disabled). Return the value.
                Sql.Query(con, queries["enable_advanced_options"]);

                return Sql.Query(con, queries["get_module_status"]).ToLower().Contains("1");
            }
        }

        /// <summary>
        /// The LinkedModuleStatus method checks if advanced options are enabled
        /// for modules via sp_configure on a linked SQL server. Logic
        /// also exists to check if rpc has been enabled, cross-checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        /// <returns></returns>
        internal static bool LinkedModuleStatus(SqlConnection con, string module, string linkedSqlServer, string[] linkedSqlServerChain = null )
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "get_module_status", string.Format(Query.GetModuleStatus, module) }
            };

            // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
            // is either a 1 (enabled) or 0 (disabled). Return the value.

            queries = linkedSqlServerChain == null
                ? Format.LinkedDictionary(linkedSqlServer, queries)
                : Format.LinkedChainDictionary(linkedSqlServerChain, queries);

            return Sql.Query(con, queries["get_module_status"]).Contains("1");
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
        ///
        internal static void ModuleToggle(SqlConnection con, string module, string value, string sqlServer, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "toggle_rpc", string.Format(Query.ToggleRpc, sqlServer, value) },
                { "enable_advanced_options", Query.EnableAdvancedOptions },
                { "toggle_module", string.Format(Query.ToggleModule, module, value) }
            };

            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }

            string sqlOutput;

            if (module.Equals("rpc"))
            {
                sqlOutput = Sql.CustomQuery(con, queries["toggle_rpc"]);

                if (sqlOutput.ToLower().Contains("does not exist"))
                {
                    Print.Error($"'{sqlServer}' does not exist.", true);
                    return;
                }

                // Convert value from true to 1, and
                // from false to 0 for the _moduleStatus method.
                value = (value.Equals("true"))
                    ? "1"
                    : "0";

                bool status = ModuleStatus(con, module, impersonate, sqlServer);

                sqlOutput = _printModuleStatus(status, module, value, sqlServer);

                if (!sqlOutput.ToLower().Contains("not have permission"))
                {
                    Console.WriteLine(_moduleStatus(con, module, impersonate, sqlServer));
                }
                else
                {
                    Console.WriteLine(sqlOutput);
                }
            }
            else
            {
                Sql.Query(con, queries["enable_advanced_options"]);

                Sql.Query(con, queries["toggle_module"]);

                bool status = ModuleStatus(con, module, impersonate, sqlServer);

                sqlOutput = _printModuleStatus(status, module, value, sqlServer);

                if (!sqlOutput.ToLower().Contains("not have permission"))
                {
                    Console.WriteLine(_moduleStatus(con, module, impersonate, sqlServer));
                }
                else
                {
                    Console.WriteLine(sqlOutput);
                }
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
        internal static void LinkedModuleToggle(SqlConnection con, string module, string value, string linkedSqlServer, string sqlServer)
        {
            // The queries dictionary contains all queries used by this module
            // The dictionary key name for RPC formatted queries must start with RPC
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "rpc_enable_advanced_configurations", Query.LinkedEnableAdvancedOptions },
                { "rpc_toggle_module", string.Format(Query.LinkedToggleModule, module, value) },
            };

            // Format all queries so that they are compatible for execution on a linked SQL server.
            queries = Format.LinkedDictionary(linkedSqlServer, queries);

            // These queries do not need to be formatted
            queries.Add( "get_links", Query.GetLinkedSqlServers);

            // Get a list of linked SQL servers.
            string sqlOutput = Sql.CustomQuery(con, queries["get_links"]);

            // Check to see if the linked SQL server exists.
            if (!sqlOutput.ToLower().Contains(linkedSqlServer.ToLower()))
            {
                Print.Error($"Error {linkedSqlServer} does not exist.", true);
                return;
            }

            // First check to see if rpc is enabled.
            if (ModuleStatus(con, "rpc", null, linkedSqlServer) == false)
            {
                Print.Error($"You need to enable RPC for {linkedSqlServer} on {sqlServer} (enablerpc /rhost:{linkedSqlServer}", true);

                Console.WriteLine(_moduleStatus(con, "rpc", null, linkedSqlServer));
                // Go no further.
                return;
            }

            Sql.CustomQuery(con, queries["rpc_enable_advanced_configurations"]);

            Sql.CustomQuery(con,  queries["rpc_toggle_module"]);

            bool status = LinkedModuleStatus(con, module, linkedSqlServer);

            sqlOutput = _printModuleStatus(status, module, value, linkedSqlServer);

            if (!sqlOutput.ToLower().Contains("not have permissions"))
            {
                Console.WriteLine(_linkedModuleStatus(con, module, linkedSqlServer));
            }
            else
            {
                Console.WriteLine(sqlOutput);
            }
        }

        /// <summary>
        /// The LinkedChainModuleToggle method will enable advanced options, then
        /// enable modules via sp_configure on a chain of linked SQL servers.
        /// Credit to Azaël MARTIN (n3rada).
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module">Common modules include: clr enabled, ole automation procedures, and xp_cmdshell.</param>
        /// <param name="value">Enable (1) or disable (0).</param>
        /// <param name="linkedSqlServerChain">An array of server names representing the chain path.</param>
        /// <param name="sqlServer"></param>
        internal static void LinkedChainModuleToggle(SqlConnection con, string module, string value, string[] linkedSqlServerChain, string sqlServer = null)
        {
            // The queries dictionary contains all queries used by this module
            // The dictionary key name for RPC formatted queries must start with RPC
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "rpc_toggle_module", string.Format(Query.LinkedChainToggleModule, module, value) }
            };

            // Format all queries so that they are compatible for execution on a linked SQL server.
            queries = Format.LinkedChainDictionary(linkedSqlServerChain, queries);

            // These queries do not need to be formatted
            queries.Add( "get_link", Query.GetLinkedSqlServers);

            // Get a list of linked SQL servers.
            string sqlOutput = Sql.CustomQuery(con, queries["get_link"]);

            // Check to see if the linked SQL server exists.
            if (!sqlOutput.ToLower().Contains(linkedSqlServerChain.First().ToLower()))
            {
                Print.Error($"Error {linkedSqlServerChain.First()} does not exist.", true);
                return;
            }

            // First check to see if rpc is enabled on the first linked host.
            bool status = ModuleStatus(con, "rpc", null, linkedSqlServerChain.First());

            if (status == false)
            {
                Print.Error($"You need to enable RPC for {linkedSqlServerChain.First()} on {sqlServer} (enablerpc /rhost:{linkedSqlServerChain.First()})", true);

                Console.WriteLine(_moduleStatus(con, "rpc", null, linkedSqlServerChain.First()));
                // Go no further.
                return;
            }

            // Attempt to toggle the module on the last server in the linked chain
            try
            {
                // Enable advanced options and the specified module on the last server in the chain.
                Sql.CustomQuery(con, queries["rpc_toggle_module"]);

                Console.WriteLine(_linkedModuleStatus(con, module, null, linkedSqlServerChain));
            }
            catch (Exception ex)
            {
                Print.Error($"Error enabling module {module} on chain: {ex.Message}", true);
            }
        }

        /// <summary>
        /// The _moduleStatus method checks if advanced options are enabled
        /// for the clr, ole or xp_cmdshell modules via sp_configure. Logic
        /// also exists to check if rpc has been enabled, cross-checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <param name="sqlServer">Optional</param>
        /// <returns></returns>
        private static string _moduleStatus(SqlConnection con, string module, string impersonate = null, string sqlServer = "")
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "get_rpc_status", string.Format(Query.GetRpcStatus, sqlServer.ToLower())},
                { "enable_advanced_options", Query.EnableAdvancedOptions},
                { "get_module_status", string.Format(Query.GetModuleStatueVerbose, module) }
            };

            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }

            if (module.Equals("rpc"))
            {
                // Obtain all SQL server names where RPC is enabled if the name matches supplied SQL server.
                return Sql.CustomQuery(con, queries["get_rpc_status"]);
            }
            else
            {
                // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
                // Return the name and value.

                Sql.CustomQuery(con, queries["enable_advanced_options"]);

                return Sql.CustomQuery(con, queries["get_module_status"]);
            }
        }

        /// <summary>
        /// The _linkedModuleStatus method checks if advanced options are enabled
        /// for modules via sp_configure on a linked SQL server. Logic
        /// also exists to check if rpc has been enabled, cross-checking the SQL server name.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="module"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        /// <returns></returns>
        private static string _linkedModuleStatus(SqlConnection con, string module, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
            // is either a 1 (enabled) or 2 (disabled). Return the name and value.

            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "get_module_status", string.Format(Query.GetModuleStatueVerbose, module) }
            };

            // Simple check to see if the supplied module (clr, ole, xp_cmdshell)
            // is either a 1 (enabled) or 0 (disabled). Return the value.

            queries = linkedSqlServerChain == null
                ? Format.LinkedDictionary(linkedSqlServer, queries)
                : Format.LinkedChainDictionary(linkedSqlServerChain, queries);

            return Sql.CustomQuery(con, queries["get_module_status"]);
        }

        /// <summary>
        /// The _printModuleStatus method validates if a module has been enabled
        /// or disabled.
        /// </summary>
        /// <param name="status"></param>
        /// <param name="value">Enable (1) or disable (0).</param>
        /// <param name="module">Common modules include: clr enabled,
        /// ole automation procedures, and xp_cmdshell.</param>
        /// <param name="sqlServer"></param>
        private static string _printModuleStatus(bool status, string module, string value, string sqlServer)
        {
            // Change the format of the string
            if (module.Equals("clr enabled"))
                module = "CLR";

            if (status == false && value.Equals("0"))
            {
                return Print.Success($"Disabled {module} on {sqlServer}.");
            }
            else if (status == true && value.Equals("1"))
            {
                return Print.Success($"Enabled {module} on {sqlServer}.");
            }
            else if (status == false && value.Equals("1"))
            {
                return Print.Error($"The current user does not have permissions to enable or disable {module} on {sqlServer}.");
            }
            else if (status == true && value.Equals("0"))
            {
                return Print.Error($"The current user does not have permissions to enable or disable {module} on {sqlServer}.");
            }
            else
            {
                return Print.Error($"The current user does not have permissions to enable or disable {module} on {sqlServer}.");
            }
        }
    }
}