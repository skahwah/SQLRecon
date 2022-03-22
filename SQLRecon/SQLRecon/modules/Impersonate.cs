using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class EnumImpersonation
    {
        public EnumImpersonation(SqlConnection con)
        {
            initialize(con);
        }

        // this checks to see if any logins can be impersonated on the sql server
        public void initialize(SqlConnection con)
        {
            try
            {
                SqlCommand command = new SqlCommand("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';", con);
                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                if (reader.HasRows)
                {
                    while (reader.Read() == true)
                    {
                        Console.WriteLine(reader[0]);
                    }
                }
                else
                {
                    Console.WriteLine("\nNo logins can be impersonated\n");
                }
                reader.Close();
                
            }
            catch (InvalidOperationException)
            {
                
            }
        } //end initialize
    }
}
