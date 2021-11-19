using System;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class CLR
    {
        // this will enable advanced options and CLR integration, which allows create assembly, etc
        public void Enable(SqlConnection con)
        {
            EnableDisable(con, "1");
        } // end Enable

        // this will disable CLR integration
        public void Disable(SqlConnection con)
        {
            EnableDisable(con, "0");

        } // end Disable

        /* this will load and execute a user supplied DLL
        public void DLL(SqlConnection con, String database, String dll)
        {
            try
            {
                String query = "ALTER DATABASE " + database + " SET TRUSTWORTHY ON; CREATE ASSEMBLY defaultassembly FROM '" + dll + "' WITH PERMISSION_SET = UNSAFE;";
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine("[+] 1: " + reader[0]);
                reader.Close();
       
                query = "CREATE PROCEDURE[dbo].[sp_mssql_default] AS EXTERNAL NAME[defaultassembly].[StoredProcedures].[sp_mssql_default];";
                command = new SqlCommand(query, con);
                reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine("[+] 2: " + reader[0]);
                reader.Close();

                query = "sp_mssql_default;";
                command = new SqlCommand(query, con);
                reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine("[+] 3: " + reader[0]);
                reader.Close();

                query = "DROP ASSEMBLY defaultassembly;";
                command = new SqlCommand(query, con);
                reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine("[+] 4: " + reader[0]);
                reader.Close();

                query = "DROP PROCEDURE sp_mssql_default;"; 
                command = new SqlCommand(query, con);
                reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine("[+] 5: " + reader[0]);
                reader.Close();

                query = "ALTER DATABASE " + database + " SET TRUSTWORTHY OFF;";
                command = new SqlCommand(query, con);
                reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();
                Console.WriteLine("[+] 6: " + reader[0]);
                reader.Close();

            }
            catch (SqlException ex)
            {
                if (ex.Errors[0].Message.ToString().Contains("permission"))
                {
                    Console.WriteLine("\n[!] ERROR: The current user does not have permissions to enable CLR integration\n");
                }
                else if (ex.Errors[0].Message.ToString().Contains("blocked"))
                {
                    Console.WriteLine("\n[!] ERROR: You need to enable CLR integration\n");

                }
                else
                {
                    Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
                }
                
            }
        } */

        public void EnableDisable(SqlConnection con, String val)
        {
            try
            {
                SqlCommand command = new SqlCommand("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'clr enabled', " + val + "; RECONFIGURE;", con);

                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                reader.Read();

                if (!reader.HasRows && val.Equals("0"))
                {
                    Console.WriteLine("[+] Successfully disabled CLR integration.\n");
                }
                else if (!reader.HasRows && val.Equals("1"))
                {
                    Console.WriteLine("[+] Successfully enabled CLR integration.\n");
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