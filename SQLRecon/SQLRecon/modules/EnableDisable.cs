using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class Configure
    {
        SQLQuery sqlQuery = new SQLQuery();

        // this will enable advanced options then enable modules via sp_configure
        public void EnableDisable(SqlConnection con, String module, String val, String impersonate = "null")
        {
            string sqlOutput = "";

            // enable (1) or disable (0) module. logic exists for impersonation.
            // common modules include:
            // xp_cmdshell
            // ole automation procedures
            // clr enabled
            if (!impersonate.Equals("null"))
            {
                sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; " +
                    "EXEC sp_configure 'show advanced options', 1; " +
                    "RECONFIGURE; " +
                    "EXEC sp_configure '" + module + "', " + val + "; " +
                    "RECONFIGURE;" +
                    "SELECT value FROM sys.configurations WHERE name = '"+ module +"';");
            }
            else
            {
                sqlOutput = sqlQuery.ExecuteQuery(con, "EXEC sp_configure 'show advanced options', 1; " +
                    "RECONFIGURE; " +
                    "EXEC sp_configure '" + module + "', " + val + "; " +
                    "RECONFIGURE;" +
                    "SELECT value FROM sys.configurations WHERE name = '" + module + "';");
            }

            ModuleLogic(sqlOutput, val, module);

        }

        public void LinkedEnableDisable(SqlConnection con, String module, String val, String linkedSqlServer)
        {
            String sqlOutput = "";

            // get a list of linked sql servers
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT name FROM sys.servers WHERE is_linked = 1;");

            // check to see if the linked sql server exists
            if (!sqlOutput.ToLower().Contains(linkedSqlServer.ToLower()))
            {
                Console.WriteLine("\n[!] ERROR: " + linkedSqlServer + " does not exist");
                return;
            }

            // check to see if RPC is enabled on the linked sql server
            sqlOutput = CheckRpc(con, linkedSqlServer);

            if (sqlOutput.Equals("0"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable RPC (enablerpc) on " + linkedSqlServer);
                return;
            }

            sqlQuery.ExecuteQuery(con, "EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT " + linkedSqlServer);
            sqlQuery.ExecuteQuery(con, "EXEC('sp_configure ''" + module + "'', "+ val +"; reconfigure;') AT " + linkedSqlServer);
            
            sqlOutput = sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "select value from sys.configurations where name = ''"+ module +"''");

            ModuleLogic(sqlOutput, val, module);
        }

        // this will enable or disable rpc out on the supplied sql server
        public string EnableDisableRpc(SqlConnection con, String val, String sqlServer)
        {
            string sqlOutput = "";

            if (val.Equals("1"))
            {
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXEC sp_serveroption '" + sqlServer + "', 'rpc out', 'true';");
            }
            else
            {
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXEC sp_serveroption '" + sqlServer + "', 'rpc out', 'false';");
            }

            if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable or disable RPC");
            }
            else if (sqlOutput.Contains("does not exist"))
            {
                Console.WriteLine("\n[!] ERROR: " + sqlServer + " does not exist");
            }
            else
            {
                sqlOutput = CheckRpc(con,  sqlServer);
                if (sqlOutput.Equals("1") && val.Equals("1"))
                {
                    Console.WriteLine("\nSUCCESS: Enabled RPC");
                }
                else if (sqlOutput.Equals("0") && val.Equals("0"))
                {
                    Console.WriteLine("\nSUCCESS: Disabled RPC");
                }
                else
                {
                    Console.WriteLine(sqlOutput);
                }
            }

            // returns 1 for enabled or 0 for disabled
            return sqlOutput;
        }

        // logic to verify if module enabled has been enabled or not.
        public void ModuleLogic(String sqlOutput, String val, String module)
        {
            if (module.Equals("clr enabled"))
            {
                module = "CLR";
            }

            if (sqlOutput.Contains("0") && val.Equals("0"))
            {
                Console.WriteLine("\nSUCCESS: Disabled " + module);
            }
            else if (sqlOutput.Contains("1") && val.Equals("1"))
            {
                Console.WriteLine("\nSUCCESS: Enabled " + module);
            }
            else if (sqlOutput.Contains("permission"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable or disable " + module);
            }
            else if (sqlOutput.Contains("0") && val.Equals("1"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable or disable " + module);
            }
            else if (sqlOutput.Contains("1") && val.Equals("0"))
            {
                Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable or disable " + module);
            }
            else
            {
                Console.WriteLine(sqlOutput);
            }
        }

        // this will check to see if advanced options for modules via sp_configure
        public string Check(SqlConnection con, String module, String impersonate = "null")
        {
            string sqlOutput = "";

            if (!impersonate.Equals("null"))
            {
                sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; " +
                    "SELECT value FROM sys.configurations WHERE name = '" + module + "';");
            }
            else
            {
                sqlOutput = sqlQuery.ExecuteQuery(con, "EXEC sp_configure 'show advanced options', 1; " +
                    "SELECT value FROM sys.configurations WHERE name = '" + module + "';");
            }

            // this will either be 0 or 1.
            return sqlOutput;
        }

        // this will check to see if advanced options for modules via sp_configure on a linkedSqlServer
        public string CheckLinked(SqlConnection con, String module, String linkedSQLServer)
        {
            string sqlOutput = "";

            sqlOutput = sqlQuery.ExecuteLinkedQuery(con, linkedSQLServer, "SELECT value FROM sys.configurations WHERE name = ''" + module + "'';");
    
            // this will either be 0 or 1.
            return sqlOutput;
        }

        // this will check to see if rpc is enabled or not
        public string CheckRpc(SqlConnection con, String sqlServer)
        {
            string sqlOutput = "";

            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXEC sp_helpserver @server='" + sqlServer + "';");

            if (sqlOutput.Contains("rpc out"))
            {
                sqlOutput = "1";
            }
            else
            {
                sqlOutput = "0";
            }

            // returns 1 for enabled or 0 for disabled
            return sqlOutput;
        }

    }
}
