using System.Data.SqlClient;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class Roles
    {
        private static readonly PrintUtils _print = new();
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The CheckServerRole method checks if a user is part of a role.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="print"></param>
        /// <returns></returns>
        public bool CheckServerRole(SqlConnection con, string role, bool print = false)
        {
            var sqlOutput = _sqlQuery.ExecuteQuery(con, 
                "SELECT IS_SRVROLEMEMBER('" + role + "');").TrimStart('\n');

            if (print)
                _roleResult(role, sqlOutput);

            return sqlOutput.Equals("1");
        }

        /// <summary>
        /// The CheckLinkedServerRole method checks if a user is part of a role on a linked SQL server.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="linkedSQLServer"></param>
        /// <param name="print"></param>
        /// <returns></returns>
        public bool CheckLinkedServerRole(SqlConnection con, string role, string linkedSQLServer, bool print = false)
        {
            var sqlOutput = _sqlQuery.ExecuteQuery(con, "select * from openquery(\"" + linkedSQLServer + "\", " +
                "'SELECT IS_SRVROLEMEMBER(''" + role + "'');')").TrimStart('\n');

            if (print)
                _roleResult(role, sqlOutput);

            return sqlOutput.Equals("1");
        }

        /// <summary>
        /// The CheckImpersonatedRole method checks the roles of an impersonated user.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="impersonate"></param>
        /// <param name="print"></param>
        /// <returns></returns>
        public bool CheckImpersonatedRole(SqlConnection con, string role, string impersonate, bool print = false)
        {
            var sqlOutput = _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                "SELECT IS_SRVROLEMEMBER('" + role + "');").TrimStart('\n');

            if (print)
                _roleResult(role, sqlOutput);

            return sqlOutput.Equals("1");
        }

        /// <summary>
        /// The _roleResult method prints if a user is part of a role or not.
        /// </summary>
        /// <param name="role"></param>
        /// <param name="sqlOutput"></param>
        private static void _roleResult(string role, string sqlOutput)
        {
            if (sqlOutput.Equals("1"))
            {
                _print.Nested(string.Format("User is a member of {0} role.", role), true);
            }
            else
            {
                _print.Nested(string.Format("User is NOT a member of {0} role.", role), true);
            }
        }
    }
}