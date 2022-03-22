using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class XPCmdShell
    {
        // this will enable advanced options then enable xp_cmdshell 
        public void Enable(SqlConnection con, String impersonate = "null")
        {
            if (!impersonate.Equals("null"))
            {
                EnableDisable(con, "1", impersonate);
            }
            else
            {
                EnableDisable(con, "1");
            }
        } // end Enable

        // this will disable XPCmdShell
        public void Disable(SqlConnection con, String impersonate = "null")
        {
            if (!impersonate.Equals("null"))
            {
                EnableDisable(con, "0", impersonate);
            }
            else
            {
                EnableDisable(con, "0");
            }
        } // end Disable

        // this will execute an arbitrary command
        public void Command(SqlConnection con, String cmd, String impersonate = "null")
        {
            try
            {

                SqlCommand command = new SqlCommand();

                if (!impersonate.Equals("null"))
                {
                    command = new SqlCommand("EXECUTE AS LOGIN = '" + impersonate + "'; EXEC xp_cmdshell '" + cmd + "';", con);
                }
                else
                {
                    command = new SqlCommand("EXEC xp_cmdshell '" + cmd + "';", con);
                }

                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine(reader[0]);
                Console.WriteLine("");
                reader.Close();
            }
            catch (SqlException ex)
            {
                if (ex.Errors[0].Message.ToString().Contains("permission"))
                {
                    Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable xp_cmdshell commands\n");
                }
                else if (ex.Errors[0].Message.ToString().Contains("blocked"))
                {
                    Console.WriteLine("\n[!] ERROR: You need to enable xp_cmdshell\n");

                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
                }
                
            }
        } // end Command

        public void EnableDisable(SqlConnection con, String val, String impersonate = "null")
        {
            try
            {
                SqlCommand command = new SqlCommand();

                if (!impersonate.Equals("null"))
                {
                    command = new SqlCommand("EXECUTE AS LOGIN = '" + impersonate + "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', " + val + "; RECONFIGURE;", con);
                }
                else
                {
                    command = new SqlCommand("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', " + val + "; RECONFIGURE;", con);
                }

                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();

                if (!reader.HasRows && val.Equals("0"))
                {
                    Console.WriteLine("[+] Successfully disabled xp_cmdshell.\n");
                }
                else if (!reader.HasRows && val.Equals("1"))
                {
                    Console.WriteLine("[+] Successfully enabled xp_cmdshell.\n");
                }
                else
                {
                    Console.WriteLine(reader[0]);
                    Console.WriteLine("");
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
            }            
        }
    }
}
