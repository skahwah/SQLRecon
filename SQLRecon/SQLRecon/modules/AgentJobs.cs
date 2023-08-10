using System;
using System.Data.SqlClient;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class AgentJobs
    {
        private static readonly Configure _config = new();
        private static readonly PrintUtils _print = new();
        private static readonly RandomString _rs = new();
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The GetAgentStatusAndJobs method checks to see if the SQL Server Agent is running.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        public void GetAgentStatusAndJobs(SqlConnection con, string sqlServer, string impersonate = "null")
        {
            // Identify if the SQL agent is running on the SQL server, use impersonation
            // if specified, if not, check the status of the agent normally.
            string sqlOutput = (impersonate.Equals("null")) 
                ? _agentStatus(con, sqlServer) 
                : _agentStatus(con, sqlServer, impersonate);

            if (sqlOutput.Contains("1"))
            {
                _print.Status(string.Format("SQL agent is running on {0}.", sqlServer), true);

                // If the SQL agent is running on the SQL server, retrieve the jobs,
                // Use impersonation if specified, if not, retrieve the jobs normally.
                sqlOutput = (impersonate.Equals("null")) 
                    ? _getAgentjobs(con, sqlServer) 
                    : _getAgentjobs(con, sqlServer, impersonate);
                
                Console.WriteLine(sqlOutput);
            }
            else
            {
                Console.WriteLine(sqlOutput);
            }
        }

        /// <summary>
        /// The GetLinkedAgentStatusAndJobs method checks to see if the SQL Server Agent
        /// is running on a Linked SQL Server.
        /// </summary>
        /// <param> 
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// </param>
        public void GetLinkedAgentStatusAndJobs(SqlConnection con, string linkedSqlServer)
        {
            string sqlOutput = _linkedAgentStatus(con, linkedSqlServer);

            if (sqlOutput.ToLower().Contains("1"))
            {

                _print.Status(string.Format("SQL agent is running on {0}.", linkedSqlServer), true);
                Console.WriteLine(_getLinkedAgentJobs(con, linkedSqlServer));
            }
            else
            {
                Console.WriteLine(sqlOutput);
            }
        }

        /// <summary>
        /// The Standard method will create a new Agent Job that will execute
        /// a supplied command using PowerShell.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="command">The commmand to execute on the remote SQL Server</param>
        public void Standard(SqlConnection con, string sqlServer, string command)
        {
            // First check to see if agent is running, if it is not then gracefully exit.
            string sqlOutput = _agentStatus(con, sqlServer);

            if (!sqlOutput.Contains("1"))
            {
                _print.Error(string.Format("The SQL agent is not running on {0}.", sqlServer), true);
                // Go no further.
                return;
            }

            // Generate a new random 8 character job name and program name
            string jobName = _rs.Generate(8); 
            string stepName = _rs.Generate(8);

            _print.Status(string.Format("Setting job_name to '{0}'.", jobName), true);
            _print.Status(string.Format("Setting step_name to '{0}'.", stepName), true);

            // Create a new SQL Agent job with the supplied command.
            _sqlQuery.ExecuteQuery(con, "use msdb;" +
                "EXEC dbo.sp_add_job @job_name = '" + jobName + "';" +
                "EXEC sp_add_jobstep @job_name = '" + jobName + "', " +
                "@step_name = '" + stepName + "', " +
                "@subsystem = 'PowerShell', " +
                "@command = '" + command + "', " +
                "@retry_attempts = 1, " +
                "@retry_interval = 5;" +
                "EXEC dbo.sp_add_jobserver @job_name = '" + jobName + "';");

            // Display all jobs.
            sqlOutput = _getAgentjobs(con, sqlServer);
            Console.WriteLine(sqlOutput);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                _print.Status(string.Format("Executing job '{0}' and waiting for 5 seconds ...", jobName), true);

                _sqlQuery.ExecuteQuery(con, "use msdb;" +
                    "EXEC dbo.sp_start_job '" + jobName + "'; " +
                    "WAITFOR DELAY '00:00:05';");

                // Delete job after it has executed.
                _sqlQuery.ExecuteQuery(con, "use msdb;" +
                    "EXEC dbo.sp_delete_job  @job_name = '" + jobName + "';");

                // Display all jobs.
                Console.WriteLine(_getAgentjobs(con, sqlServer));
                _print.Success(string.Format("Deleting job '{0}' on {1}.", jobName, sqlServer), true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                _print.Error(string.Format("The current user does not have permissions to create new jobs on {0}.", sqlServer), true);
            }
            else
            {
                _print.Error(string.Format("Unable to create new job '{0}' on {1}.", jobName, sqlServer), true);
            }
        }

        /// <summary>
        /// The Impersonate method will create a new Agent Job that will execute
        /// a supplied command using PowerShell and using impersonation.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="command"></param>
        /// <param name="impersonate"></param>
        public void Impersonate(SqlConnection con, string sqlServer, string command, string impersonate)
        {
            string sqlOutput = _agentStatus(con, sqlServer, impersonate);

            // First check to see if agent is running, if it is not then gracefully exit.
            if (!sqlOutput.Contains("1"))
            {
                _print.Error(string.Format("The SQL agent is not running on {0}.", sqlServer), true);
                // Go no further.
                return;
            }

            // Generate a new random 8 character job name and program name.
            string jobName = _rs.Generate(8);
            string stepName = _rs.Generate(8);

            _print.Status(string.Format("Setting job_name to '{0}'.", jobName), true);
            _print.Status(string.Format("Setting step_name to '{0}'.", stepName), true);

            _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                "use msdb;" +
                "EXEC dbo.sp_add_job @job_name = '" + jobName + "';" +
                "EXEC sp_add_jobstep @job_name = '" + jobName + "', " +
                "@step_name = '" + stepName + "', " +
                "@subsystem = 'PowerShell', " +
                "@command = '" + command + "', " +
                "@retry_attempts = 1, " +
                "@retry_interval = 5;" +
                "EXEC dbo.sp_add_jobserver @job_name = '" + jobName + "';");

            // Display all jobs.
            sqlOutput = _getAgentjobs(con, sqlServer, impersonate);
            Console.WriteLine(sqlOutput);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                _print.Status(string.Format("Executing job '{0}' and waiting for 5 seconds ...", jobName), true);

                _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                    "use msdb;" +
                    "EXEC dbo.sp_start_job '" + jobName + "';" +
                    " WAITFOR DELAY '00:00:05';");

                // Delete job after it has executed.
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                    "use msdb; " +
                    "EXEC dbo.sp_delete_job  @job_name = '" + jobName + "';");

                // Display all jobs.
                Console.WriteLine(_getAgentjobs(con, sqlServer, impersonate));
                _print.Success(string.Format("Deleting job '{0}' on {1}.", jobName, sqlServer), true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                _print.Error(string.Format("The current user does not have permissions to create new jobs on {0}.", sqlServer), true);
            }
            else
            {
                _print.Error(string.Format("Unable to create new job '{0}' on {1}.", jobName, sqlServer), true);
            }
        }

        /// <summary>
        /// The Linked method will create a new Agent Job that will execute
        /// a supplied command using a subsystem, such as PowerShell on a Linked SQL Server.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="subSystem"></param>
        /// <param name="command"></param>
        /// <param name="sqlServer"></param>
        public void Linked(SqlConnection con, string linkedSqlServer, string subSystem, string command, string sqlServer)
        {
            string sqlOutput = _linkedAgentStatus(con, linkedSqlServer);

            // First check to see if agent is running, if it is not then gracefully exit.
            if (!sqlOutput.Contains("1"))
            {
                _print.Error(string.Format("The SQL agent is not running on {0}.", linkedSqlServer), true);
                // Go no further.
                return;
            }

            // Then check to see if rpc is enabled.
            sqlOutput = _config.ModuleStatus(con, "rpc", "null", linkedSqlServer);
            if (!sqlOutput.Contains("1"))
            {
                _print.Error(string.Format("You need to enable RPC for {1} on {0} (enablerpc -o {1}).",
                    sqlServer, linkedSqlServer), true);
                // Go no futher.
                return;
            }

            // Generate a new random 8 character job name and program name.
            string jobName = _rs.Generate(8);
            string stepName = _rs.Generate(8);

            _print.Status(string.Format("Setting job_name to '{0}'.", jobName), true);
            _print.Status(string.Format("Setting step_name to '{0}'.", stepName), true);

            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "use msdb;" +
                "EXEC dbo.sp_add_job @job_name = ''" + jobName + "'';" +
                "EXEC dbo.sp_add_jobstep @job_name = ''" + jobName + "'', " +
                "@step_name = ''" + stepName + "'', " +
                "@subsystem = ''" + subSystem + "'', " +
                "@command = ''" + command + "'', " +
                "@retry_attempts = 1, " +
                "@retry_interval = 5;" +
                "EXEC dbo.sp_add_jobserver @job_name = ''" + jobName + "'';");

            // Display all jobs.
            sqlOutput = _getLinkedAgentJobs(con, linkedSqlServer);
            Console.WriteLine(sqlOutput);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                _print.Status(string.Format("Executing job '{0}' and waiting for 5 seconds ...", jobName), true);

                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "use msdb;" +
                    "EXEC dbo.sp_start_job ''" + jobName + "''; " +
                    "WAITFOR DELAY ''00:00:05'';");

                // Delete job after it has executed.
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "use msdb;" +
                    "EXEC dbo.sp_delete_job  @job_name = ''" + jobName + "'';");

                // Display all jobs.
                Console.WriteLine(_getLinkedAgentJobs(con, linkedSqlServer));
                _print.Success(string.Format("Deleting job '{0}' on {1}.", jobName, linkedSqlServer), true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                _print.Error(string.Format("The current user does not have permissions to create new jobs on {0}.", linkedSqlServer), true);
            }
            else
            {
                _print.Error(string.Format("Unable to create new job '{0}' on {1}.", jobName, linkedSqlServer), true);
            }
        }

        /// <summary>
        /// The _agentStatus method checks to see if the SQL Agent is running on the specified server
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <returns>All agent jobs running on the specified SQL server.</returns>
        private string _agentStatus(SqlConnection con, string sqlServer, string impersonate = "null")
        {
            // Identify if the SQL agent is running on the SQL server, use impersonation
            // if specified, if not, check the status of the agent normally.
            string sqlOutput = (impersonate.Equals("null"))
                ? _sqlQuery.ExecuteCustomQuery(con,
                    "SELECT dss.[status], dss.[status_desc] FROM sys.dm_server_services dss " +
                    "WHERE dss.[servicename] LIKE 'SQL Server Agent (%';")
                : _sqlQuery.ExecuteImpersonationCustomQuery(con, impersonate,
                    "SELECT dss.[status], dss.[status_desc] FROM sys.dm_server_services dss " +
                    "WHERE dss.[servicename] LIKE 'SQL Server Agent (%';");

            if (sqlOutput.ToLower().Contains("running"))
            {
                return "1";
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return _print.Error(string.Format("The current user does not have permissions to view agent information on {0}.", sqlServer));
            }
            else
            {
                return _print.Status(string.Format("SQL agent is not running on {0}.", sqlServer));
            }
        }

        /// <summary>
        /// The _linkedAgentStatus method checks to see if the SQL Agent is running on the Linked SQL server
        /// </summary>
        /// <param> 
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// </param>
        /// <returns></returns>
        private string _linkedAgentStatus(SqlConnection con, string linkedSqlServer)
        {
            string sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer,
                "SELECT dss.[status], dss.[status_desc]" +
                "FROM sys.dm_server_services dss WHERE dss.[servicename] LIKE ''SQL Server Agent (%'';");

            if (sqlOutput.ToLower().Contains("running"))
            {
                return "1";
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return _print.Error(string.Format("The current user does not have permissions to view agent information on {0}.", linkedSqlServer));
            }
            else
            {
                return _print.Status(string.Format("SQL agent is not running on {0}.", linkedSqlServer));
            }
        }

        /// <summary>
        /// The _getAgentjobs method is responsible for gathering SQL Agent jobs.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="sqlServer"></param>
        /// <param name="impersonate">This is an optional parameter that is activated when impersonation is selected.</param>
        /// <returns>All agent jobs running on the specified SQL server.</returns>
        private string _getAgentjobs(SqlConnection con, string sqlServer, string impersonate = "null")
        {
            // If the SQL agent is running on the SQL server, retrieve the jobs,
            // Use impersonation if specified, if not, retrieve the jobs normally.
            string sqlOutput = (impersonate.Equals("null"))
                ? _sqlQuery.ExecuteCustomQuery(con, "SELECT job_id, name, enabled, " +
                "date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created")
                : _sqlQuery.ExecuteImpersonationCustomQuery(con, impersonate,
                "SELECT job_id, name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created");

            if (sqlOutput.ToLower().Contains("job_id"))
            {
                return _print.Status(string.Format("Agent Jobs on {0}\n{1}", sqlServer, sqlOutput));
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return _print.Error(string.Format("The current user does not have permissions to view agent information on {0}.", sqlServer));
            }
            else
            {
                return _print.Status(string.Format("There are no jobs on {0}.", sqlServer));
            }
        }

        /// <summary>
        /// The _getLinkedAgentjobs method is responsible for gathering SQL Agent jobs from Linked SQL servers.
        /// </summary>
        /// <param> 
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// /// </param>
        /// <returns>All agent jobs running on the Linked SQL server.</returns>
        private string _getLinkedAgentJobs(SqlConnection con, string linkedSqlServer)
        {
            string sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer,
                "SELECT job_id, name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created");

            if (sqlOutput.ToLower().Contains("job_id"))
            {
                return _print.Status(string.Format("Agent Jobs on {0}\n{1}", linkedSqlServer, sqlOutput));
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return _print.Error(string.Format("The current user does not have permissions to view agent information on {0}.", linkedSqlServer));
            }
            else
            {
                return _print.Status(string.Format("There are no jobs on {0}.", linkedSqlServer));
            }
        }
    }
}