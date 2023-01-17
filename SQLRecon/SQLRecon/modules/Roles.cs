using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class Roles
    {
        private readonly SQLQuery _sqlQuery = new();

        /// <summary>
        /// Check to see if a user is part of a role
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="print"></param>
        /// <returns></returns>
        public bool CheckServerRole(SqlConnection con, string role, bool print = false)
        {
            var output = _sqlQuery.ExecuteQuery(con, "SELECT IS_SRVROLEMEMBER('" + role + "');").TrimStart('\n');

            if (print)
                RoleResult(role, output);

            return output.Equals("1");
        }

        /// <summary>
        /// Check to see if a user is part of a role on a linked SQL server
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="linkedSQLServer"></param>
        /// <param name="print"></param>
        /// <returns></returns>
        public bool CheckLinkedServerRole(SqlConnection con, string role, string linkedSQLServer, bool print = false)
        {
            var output = _sqlQuery.ExecuteQuery(con, "select * from openquery(\"" + linkedSQLServer + "\", 'SELECT IS_SRVROLEMEMBER(''" + role + "'');')").TrimStart('\n');

            if (print)
                RoleResult(role, output);

            return output.Equals("1");
        }

        /// <summary>
        /// Check the roles of an impersonated user 
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="impersonate"></param>
        /// <param name="print"></param>
        /// <returns></returns>
        public bool CheckImpersonatedRole(SqlConnection con, string role, string impersonate, bool print = false)
        {
            var output = _sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';SELECT IS_SRVROLEMEMBER('" + role + "');").TrimStart('\n');

            if (print)
                RoleResult(role, output);

            return output.Equals("1");
        }

        private static void RoleResult(string role, string sqlOutput)
        {
            if (sqlOutput.Equals("1"))
            {
                Console.WriteLine("User is a member of " + role + " role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of " + role + " role");
            }
        }
    }
}