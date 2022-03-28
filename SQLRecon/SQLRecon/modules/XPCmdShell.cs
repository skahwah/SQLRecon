using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class XPCmdShell
    {
        SQLQuery sqlQuery = new SQLQuery();
        Configure config = new Configure();

        // this executes a command against a sql server
        public void StandardCommand(SqlConnection con, String cmd)
        {

            string sqlOutput = "";
            
            // first check to see if xp_cmdshell s is enabled
            sqlOutput = config.Check(con, "xp_cmdshell");

            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell (enablexp).");
                return;
            }

            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXEC xp_cmdshell '" + cmd + "';");

            if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to issue xp_cmdshell commands");
            }
            else if (sqlOutput.Contains("blocked"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell (enablexp)");
            }
            else
            {
                // this is the output
                Console.WriteLine(sqlOutput);
            }
        } 

        // this executes a command against a sql server using impersonation
        public void ImpersonateCommand(SqlConnection con, String cmd, String impersonate)
        {
            string sqlOutput = "";

            // first check to see if xp_cmdshell s is enabled
            sqlOutput = config.Check(con, "xp_cmdshell", impersonate);

            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell (ienablexp).");
                return;
            }

            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; EXEC xp_cmdshell '" + cmd + "';");

            if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable xp_cmdshell commands");
            }
            else if (sqlOutput.Contains("blocked"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell (ienablexp)");
            }
            else
            {
                // this is the output
                Console.WriteLine(sqlOutput);
            }   
        }

        // this executes a command against a linked sql server using 
        public void LinkedCommand(SqlConnection con, String cmd, String linkedSqlServer)
        {

            string sqlOutput = "";

            // first check to see if xp_cmdshell is enabled
            sqlOutput = config.CheckLinked(con, "xp_cmdshell", linkedSqlServer);

            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell (ienablexp).");
                return;
            }

            sqlOutput = sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "select 1; exec master..xp_cmdshell ''" + cmd + "''");

            if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable xp_cmdshell commands");
            }
            else if (sqlOutput.Contains("blocked"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell (lenablexp)");
            }
            else
            {
                // this is the output
                if (sqlOutput.Contains("1"))
                {
                    Console.WriteLine("\nSUCCESS: Command Executed");
                }
            }
        }
    }
}