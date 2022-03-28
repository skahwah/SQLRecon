using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class Roles
    {
        SQLQuery sqlQuery = new SQLQuery();

        // this will check to see if a user is part of a role
        public void Server(SqlConnection con, String role)
        {
            string sqlOutput = "";
            sqlOutput = sqlQuery.ExecuteQuery(con,"SELECT IS_SRVROLEMEMBER('" + role + "');");
            RoleResult(role, sqlOutput);
        }

        // this will check to see if a user is part of a role on a linked SQL server
        public void Linked(SqlConnection con, String role, String linkedSQLServer)
        {
            string sqlOutput = "";
            sqlOutput = sqlQuery.ExecuteQuery(con, "select * from openquery(\"" + linkedSQLServer + "\", 'SELECT IS_SRVROLEMEMBER(''" + role +"'');')");
            RoleResult(role, sqlOutput);
        }

        // this will check the roles of an impersonated user
        public void Impersonate(SqlConnection con, String role, String impersonate)
        {
            string sqlOutput = "";
            sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';SELECT IS_SRVROLEMEMBER('" + role + "');");
            RoleResult(role, sqlOutput);
        }

        public void RoleResult(string role, string sqlOutput)
        {
            if (sqlOutput.Contains("1"))
            {
                Console.WriteLine("User is a member of " + role + " role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of " + role + " role\n");
            }
        }
    }
}

