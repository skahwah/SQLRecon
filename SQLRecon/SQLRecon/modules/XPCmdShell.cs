using System.Collections.Generic;
using System.Data.SqlClient;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class XpCmdShell
    {
        /// <summary>
        /// The StandardOrImpersonation method executes an arbitrary command on 
        /// a remote SQL server using xp_cmdshell. Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="impersonate"></param>
        internal static void StandardOrImpersonation(SqlConnection con, string cmd, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "xpcmd", string.Format(Query.XpCmd, cmd)}
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }

            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }
            
            // First check to see if xp_cmdshell is enabled. 
            // Impersonation is supported.
            bool status = (string.IsNullOrEmpty(impersonate))
                ? Config.ModuleStatus(con, "xp_cmdshell")
                : Config.ModuleStatus(con, "xp_cmdshell", impersonate);

            if (status == false)
            {
                Print.Error("You need to enable xp_cmdshell (enablexp).", true);
                // Go no further.
                return;
            }
            
            _printStatus(cmd, Sql.CustomQuery(con, queries["xpcmd"]));
        }
        
        /// <summary>
        /// The LinkedOrChain method executes an arbitrary command on 
        /// a remote linked SQL server using xp_cmdshell.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        internal static void LinkedOrChain(SqlConnection con, string cmd, string linkedSqlServer, string[] linkedSqlServerChain = null )
        {
            bool status;
            
            // The queries dictionary contains all queries used by this module
            // The dictionary key name for RPC formatted queries must start with RPC
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "xpcmd", string.Format(Query.LinkedXpCmd, cmd)}
            };
            
            if (linkedSqlServerChain == null)
            {
                // Format all queries so that they are compatible for execution on a linked SQL server.
                queries = Format.LinkedDictionary(linkedSqlServer, queries);
                
                // First check to see if xp_cmdshell is enabled.
                status = Config.LinkedModuleStatus(con, "xp_cmdshell", linkedSqlServer);
            }
            else
            {
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                queries = Format.LinkedChainDictionary(linkedSqlServerChain, queries);
                
                // First check to see if xp_cmdshell is enabled.
                status = Config.LinkedModuleStatus(con, "xp_cmdshell", null, linkedSqlServerChain);
            }
            
            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            } 
            
            if (status == false)
            {
                Print.Error("You need to enable xp_cmdshell (enablexp).", true);
                // Go no further.
                return;
            }
            
            _printStatus(cmd, Sql.CustomQuery(con, queries["xpcmd"]));
        }

        /// <summary>
        /// The _printStatus method will display the status of the 
        /// xp_cmdshell command execution.
        /// </summary>
        /// <param name="cmd"></param>
        /// <param name="sqlOutput"></param>
        private static void _printStatus(string cmd, string sqlOutput)
        {
            if (sqlOutput.ToLower().Contains("permission"))
            {
                Print.Error("You do not have the correct privileges to perform this action.", true);
            }
            else if (sqlOutput.ToLower().Contains("execution timeout expired"))
            {
                Print.Status($"'{cmd}' executed.", true);

            }    
            else if (sqlOutput.ToLower().Contains("blocked"))
            {
                Print.Error("You need to enable xp_cmdshell.", true);
            }
            else
            {
                Print.IsOutputEmpty(sqlOutput, true);
            }
        }
    }
}