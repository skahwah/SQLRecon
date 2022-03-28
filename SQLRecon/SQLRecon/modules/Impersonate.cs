using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class Impersonate
    {
        SQLQuery sqlQuery = new SQLQuery();

        // this checks to see if any logins can be impersonated on the sql server
        public void Check(SqlConnection con)
        {
            string sqlOutput = "";
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';");

            if (sqlOutput.Contains("name"))
            {
                Console.WriteLine(sqlOutput);
            }
            else
            {
                Console.WriteLine("\nNo logins can be impersonated");
            }
        } 
    }
}