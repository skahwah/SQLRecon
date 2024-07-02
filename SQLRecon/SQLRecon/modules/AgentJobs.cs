using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class AgentJobs
    {
        /// <summary>
        /// The GetAgentStatusAndJobs method checks to see if the SQL Server Agent is running.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        internal static void GetAgentStatusAndJobs(SqlConnection con, string sqlServer, string impersonate = null)
        {
            // Identify if the SQL agent is running on the SQL server, use impersonation
            // if specified, if not, check the status of the agent normally.
            bool checkAgentStatus = (string.IsNullOrEmpty(impersonate)) 
                ? _agentStatus(con, sqlServer) 
                : _agentStatus(con, sqlServer, impersonate);

            if (checkAgentStatus)
            {
                Print.Status($"SQL agent is running on {sqlServer}.", true);

                // If the SQL agent is running on the SQL server, retrieve the jobs,
                // Use impersonation if specified, if not, retrieve the jobs normally.
                string sqlOutput = (string.IsNullOrEmpty(impersonate)) 
                    ? _getAgentjobs(con, sqlServer) 
                    : _getAgentjobs(con, sqlServer, impersonate);
                
                Console.WriteLine(sqlOutput);
            }
        }

        /// <summary>
        /// The GetLinkedAgentStatusAndJobs method checks to see if the SQL Server Agent
        /// is running on a Linked SQL Server.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        internal static void GetLinkedAgentStatusAndJobs(SqlConnection con, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            if (linkedSqlServerChain == null)
            {
                if (!_linkedAgentStatus(con, linkedSqlServer)) return;
                
                Print.Status($"SQL agent is running on {linkedSqlServer}.", true);
                Console.WriteLine(_getLinkedAgentJobs(con, linkedSqlServer));
            }
            else
            {
                if (!_linkedAgentStatus(con, linkedSqlServer, linkedSqlServerChain)) return;
                
                Print.Status($"SQL agent is running on {linkedSqlServerChain.Last()}.", true);
                Console.WriteLine(_getLinkedAgentJobs(con, linkedSqlServer, linkedSqlServerChain));
            }
        }

        /// <summary>
        /// The StandardOrImpersonation method will create a new Agent Job that will execute
        /// a supplied command using a subsystem, such as PowerShell. Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="subSystem"></param>
        /// <param name="command">The commmand to execute on the remote SQL Server</param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        internal static void StandardOrImpersonation(SqlConnection con, string sqlServer, string subSystem, string command, string impersonate = null)
        {
            // Generate a new random 8 character job name and program name
            string jobName = RandomStr.Generate(8); 
            string stepName = RandomStr.Generate(8);
            
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            { 
                { "create_job", string.Format(Query.CreateAgentJob, jobName, stepName, subSystem, command) },
                { "execute_job", string.Format(Query.ExecuteAgentJob, jobName) },
                { "delete_job",  string.Format(Query.DeleteAgentJob, jobName) }
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
            
            // First check to see if agent is running, if it is not then gracefully exit.
            // Impersonation is considered.
            bool checkAgentStatus =  (string.IsNullOrEmpty(impersonate))
                ? _agentStatus(con, sqlServer)
                : _agentStatus(con, sqlServer, impersonate);
            
            if (checkAgentStatus == false)
            {
                // Go no further.
                return;
            }
            
            Print.Status($"Setting job_name to '{jobName}'.", true);
            Print.Status($"Setting step_name to '{stepName}'.", true);

            // Create a new SQL Agent job with the supplied command.
            // Impersonation is considered.
            Sql.Query(con, queries["create_job"]);
            
            // Display all jobs. Impersonation is considered.
            string sqlOutput = (string.IsNullOrEmpty(impersonate))
                ? _getAgentjobs(con, sqlServer)
                : _getAgentjobs(con, sqlServer, impersonate);
            
            Console.WriteLine(sqlOutput);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                Print.Status($"Executing job '{jobName}' and waiting for 5 seconds ...", true);

                // Execute created job. Impersonation is considered.
                Sql.Query(con, queries["execute_job"]);

                // Delete job after it has executed. Impersonation is considered.
                Sql.Query(con, queries["delete_job"]);

                // Display all jobs. Impersonation is considered.
                sqlOutput = (string.IsNullOrEmpty(impersonate))
                    ? _getAgentjobs(con, sqlServer)
                    : _getAgentjobs(con, sqlServer, impersonate);
                
                Console.WriteLine(sqlOutput);
                
                Print.Success($"Deleted job '{jobName}' on {sqlServer}.", true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                Print.Error($"The current user does not have permissions to create new jobs on {sqlServer}.", true);
            }
            else
            {
                Print.Error($"Unable to create new job '{jobName}' on {sqlServer}.", true);
            }
        }

        /// <summary>
        /// The LinkedOrChain method will create a new Agent Job that will execute
        /// a supplied command using a subsystem, such as PowerShell on a Linked SQL Server.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="subSystem"></param>
        /// <param name="command"></param>
        /// <param name="sqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        internal static void LinkedOrChain(SqlConnection con, string linkedSqlServer, string subSystem, string command, string sqlServer, string[] linkedSqlServerChain = null)
        {
            // Generate a new random 8 character job name and program name
            string jobName = RandomStr.Generate(8); 
            string stepName = RandomStr.Generate(8);
            
            // The queries dictionary contains all queries used by this module
            // The dictionary key name for RPC formatted queries must start with RPC 
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "rpc_create_job" ,string.Format(Query.CreateAgentJob, jobName, stepName, subSystem, command ) },  
                { "rpc_execute_job" ,string.Format(Query.ExecuteAgentJob, jobName) },  
                { "rpc_delete_job" ,string.Format(Query.DeleteAgentJob, jobName) }  
            };

            if (linkedSqlServerChain == null)
            {
                // Format all queries so that they are compatible for execution on a linked SQL server.
                queries = Format.LinkedDictionary(linkedSqlServer, queries);
            }
            else
            {
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                queries = Format.LinkedChainDictionary(linkedSqlServerChain, queries);
                linkedSqlServer = linkedSqlServerChain.Last();
            }
            
            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }
            
            // First check to see if agent is running, if it is not then gracefully exit.
            if (_linkedAgentStatus(con, linkedSqlServer, linkedSqlServerChain) == false)
            {
                // Go no further.
                return;
            }

            // Then check to see if rpc is enabled.
            if (Config.ModuleStatus(con, "rpc", null, linkedSqlServer) == false)
            {
                Print.Error($"You need to enable RPC for {linkedSqlServer} on {sqlServer} (/m:enablerpc /rhost:{linkedSqlServer}).", true);
                // Go no further.
                return;
            }
            
            Print.Status($"Setting job_name to '{jobName}'.", true);
            Print.Status($"Setting step_name to '{stepName}'.", true);

            Sql.CustomQuery(con, queries["rpc_create_job"]);

            // Display all jobs.
            string sqlOutput = _getLinkedAgentJobs(con, linkedSqlServer, linkedSqlServerChain);
            
            Console.WriteLine(sqlOutput);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                Print.Status($"Executing job '{jobName}' and waiting for 5 seconds ...", true);

                Sql.CustomQuery(con, queries["rpc_execute_job"]);

                // Delete job after it has executed.
                Sql.CustomQuery(con, queries["rpc_delete_job"]);

                // Display all jobs.
                Console.WriteLine(_getLinkedAgentJobs(con, linkedSqlServer, linkedSqlServerChain));
                
                Print.Success($"Deleting job '{jobName}' on {linkedSqlServer}.", true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                Print.Error($"The current user does not have permissions to create new jobs on {linkedSqlServer}.", true);
            }
            else
            {
                Print.Error($"Unable to create new job '{jobName}' on {linkedSqlServer}.", true);
            }
        }

        /// <summary>
        /// The _agentStatus method checks to see if the SQL Agent is running on the specified server
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <returns>Agent status on the remote SQL server</returns>
        private static bool _agentStatus(SqlConnection con, string sqlServer, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "agent_status", Query.GetAgentStatus }
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
                // Falsify that the agent is running so that _getAgentjobs can be entered via GetAgentStatusAndJobs.
                return true;
            }  
            
            // Identify if the SQL agent is running on the SQL server, use impersonation
            // if specified, if not, check the status of the agent normally.
            string sqlOutput = Sql.CustomQuery(con, queries["agent_status"]);
            
            if (sqlOutput.ToLower().Contains("running"))
            {
                return true;
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                Print.Error($"The current user does not have permissions to view agent information on {sqlServer}.", true);
                return false; 
                    
            }
            else
            {
                Print.Status($"SQL agent is not running on {sqlServer}.", true);
                return false;
            }
        }

        /// <summary>
        /// The _linkedAgentStatus method checks to see if the SQL Agent is running on the Linked SQL server
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        /// <returns>Agent status on the specified linked SQL server.</returns>
        private static bool _linkedAgentStatus(SqlConnection con, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "agent_status", Query.GetAgentStatus }
            };

            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Falsify that the agent is running so that _getLinkedAgentjobs can be entered via GetLinkedAgentStatusAndJobs.
                return true;
            }
            
            queries = (linkedSqlServerChain == null) 
                // Format all queries so that they are compatible for execution on a linked SQL server.
                ? Format.LinkedDictionary(linkedSqlServer, queries)
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                : Format.LinkedChainDictionary(linkedSqlServerChain, queries);
            
            string sqlOutput = Sql.CustomQuery(con, queries["agent_status"]);

            if (sqlOutput.ToLower().Contains("running"))
            {
                return true;
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                Print.Error($"The current user does not have permissions to view agent information on {linkedSqlServer}.", true);
                return false;
            }
            else
            {
                Print.Status($"SQL agent is not running on {linkedSqlServer}.", true);
                return false;
            }
        }

        /// <summary>
        /// The _getAgentjobs method is responsible for gathering SQL Agent jobs.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <returns>All agent jobs running on the specified SQL server.</returns>
        private static string _getAgentjobs(SqlConnection con, string sqlServer, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "agent_jobs", Query.GetAgentJobs }
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
                // Falsify that the agent is running so that _getAgentjobs can be entered.
                return "1";
            }  
            
            // If the SQL agent is running on the SQL server, retrieve the jobs,
            // Use impersonation if specified, if not, retrieve the jobs normally.
            string sqlOutput =  Sql.CustomQuery(con, queries["agent_jobs"]);

            if (sqlOutput.ToLower().Contains("job_id"))
            {
                return Print.Status($"Agent Jobs on {sqlServer}\n\n{sqlOutput}"); 
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return Print.Error($"The current user does not have permissions to view agent information on {sqlServer}.");
            }
            else
            {
                return Print.Status($"There are no jobs on {sqlServer}.");
            }
        }

        /// <summary>
        /// The _getLinkedAgentjobs method is responsible for gathering SQL Agent jobs from Linked SQL servers.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        /// <returns>All agent jobs running on the Linked SQL server.</returns>
        private static string _getLinkedAgentJobs(SqlConnection con, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "agent_jobs", Query.GetAgentJobs }
            };

            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Falsify that the agent is running so that _getLinkedAgentjobs can be entered.
                return "1";
            }

            if (linkedSqlServerChain == null)
            {
                // Format all queries so that they are compatible for execution on a linked SQL server.
                queries = Format.LinkedDictionary(linkedSqlServer, queries);
            }
            else
            {
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                queries = Format.LinkedChainDictionary(linkedSqlServerChain, queries);
                linkedSqlServer = linkedSqlServerChain.Last();
            }
            
            string sqlOutput = Sql.CustomQuery(con, queries["agent_jobs"]);

            if (sqlOutput.ToLower().Contains("job_id"))
            {
                return Print.Status($"Agent Jobs on {linkedSqlServer}\n\n{sqlOutput}");
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return Print.Error($"The current user does not have permissions to view agent information on {linkedSqlServer}.");
            }
            else
            {
                return ($"There are no jobs on {linkedSqlServer}.");
            }
        }
    }
}