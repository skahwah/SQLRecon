using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Data.SqlClient;
using System.Text;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class SqlQuery
    {
        private static readonly PrintUtils _print = new();

        /// <summary>
        /// The ExecuteQuery method is used to execute a query against a SQL
        /// server. This method expects that the output only returns one value
        /// on a single line and does not account for multi-line returns.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteQuery(SqlConnection con, string query)
        {
            string sqlString = "";

            try
            {
                SqlCommand command = new(query, con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    sqlString += reader[0];
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }

            return sqlString;
        }

        /// <summary>
        /// The ExecuteCustomQuery method is used to execute a query against a SQL
        /// server. This method expects that the output returns multiple lines.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteCustomQuery(SqlConnection con, string query)
        {
            string sqlString = "";

            try
            {
                SqlCommand command = new(query, con);
                SqlDataReader reader = command.ExecuteReader();
                using (reader)
                {
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        int columnCount = 0;

                        // Print the column names.
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (reader.GetName(i).Equals(""))
                            {
                                // On some occasions, there may not be a column name returned, so we add one.
                                columnName = "column" + i.ToString() + " | ";
                            }
                            else
                            {
                                columnName = reader.GetName(i) + " | ";
                            }
                            sqlString += columnName;
                            hyphenCount += columnName.Length;
                            columnCount += 1;
                        }

                        sqlString += "\n";
                        sqlString += new String('-', hyphenCount);
                        sqlString += "\n";

                        // Retrieve data from the SQL data reader.
                        while (reader.Read())
                        {
                            // Apply formatting if there is more than one column.
                            if (columnCount <= 1)
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    sqlString += reader.GetValue(i) + " | " + "\n";
                                }
                            }
                            // Apply formatting if there is more than one column.
                            else
                            {

                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    if (i == (columnCount - 1))
                                    {
                                        sqlString += reader.GetValue(i) + " | \n";
                                    }
                                    else
                                    {
                                        sqlString += reader.GetValue(i) + " | ";
                                    }
                                }
                            }
                        }

                        // Remove the last few characters, wich consist of a space, pipe, space.
                        sqlString = sqlString.Remove(sqlString.Length - 2);
                    }
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }
            return sqlString;
        }


        /// <summary>
        /// Checks if the current user can impersonate another user in SQL Server.
        /// This method first determines if the current user has 'sysadmin' privileges.
        /// If the user is a 'sysadmin', they can impersonate any user, and the method returns true.
        /// If not a 'sysadmin', the method checks if the current user has the permission
        /// to impersonate the specified user by checking the 'IMPERSONATE' permissions in SQL Server.
        /// If a specific user is not provided, the method assumes no impersonation is needed
        /// and returns true, indicating that the operation can proceed without impersonation.
        /// </summary>
        /// <param name="con">The SQL connection to use for executing the check.</param>
        /// <param name="impersonate">The username of the user to check impersonation permissions for.
        /// If null or empty, the method returns true, assuming no impersonation is required.</param>
        /// <returns>True if the current user can impersonate the specified user or is a 'sysadmin',
        /// false otherwise.</returns>
        public bool CanImpersonate(SqlConnection con, string impersonate = null)
        {
            // Check if the current user is a sysadmin.
            string sysAdminCheckQuery = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            SqlCommand sysAdminCommand = new(sysAdminCheckQuery, con);

            object result = sysAdminCommand.ExecuteScalar();
            bool isAdmin = result != null && result.ToString() == "1";

            // If the user is a sysadmin, return true, as they can impersonate any user.
            if (isAdmin)
            {
                return true;
            }

            // If impersonation is not needed, just return true (no specific user to impersonate)
            if (string.IsNullOrEmpty(impersonate))
            {
                return true;
            }

            // Check if the specific user can be impersonated
            string impersonateQuery = $"SELECT 1 FROM sys.server_permissions a " +
                                      $"INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id " +
                                      $"WHERE a.permission_name = 'IMPERSONATE' AND b.name = '{impersonate.Replace("'", "''")}'";

            SqlCommand impersonateCommand = new(impersonateQuery, con);
            object impersonateResult = impersonateCommand.ExecuteScalar();

            // If any result is returned, the user can be impersonated
            return impersonateResult != null;
        }


        /// <summary>
        /// The ExecuteImpersonationQuery method is used to execute
        /// a query against a SQL server using impersonation. It first checks if the user has
        /// the necessary permissions or is a sysadmin. Error handling
        /// is performed to ensure that the impersonated user exists and can be impersonated
        /// before executing the query. This method expects that the output only returns one value
        /// on a single line and does not account for multi-line returns.
        /// </summary>
        /// <param name="con">The SQL connection.</param>
        /// <param name="impersonate">The user to impersonate.</param>
        /// <param name="query">The SQL query to execute.</param>
        /// <returns>The query result or an error message.</returns>
        public string ExecuteImpersonationQuery(SqlConnection con, string impersonate, string query)
        {
            // Use the CanImpersonate method to check if the current user can impersonate the specified user.
            if (CanImpersonate(con, impersonate))
            {
                // Construct and execute the query with impersonation.
                string impersonationQuery = $"EXECUTE AS LOGIN = '{impersonate}'; {query}; REVERT;";
                string result = ExecuteQuery(con, impersonationQuery);

                return result.ToLower().Contains("cannot execute as the server principal")
                    ? _print.Error($"The {impersonate} login cannot be impersonated.")
                    : result;
            }
            else
            {
                // The user cannot be impersonated or the current user does not have sufficient privileges.
                return _print.Error($"The {impersonate} login cannot be impersonated or you do not have sufficient privileges.");
            }
        }

        /// <summary>
        /// Attempts to impersonate a specified user within the context of a given SQL connection.
        /// This method checks if the current connected user can impersonate the specified user and,
        /// if permitted, executes the impersonation. It provides feedback on the success or failure
        /// of the impersonation attempt.
        /// </summary>
        /// <param name="con">The active SQL connection over which the impersonation attempt will be made.</param>
        /// <param name="impersonate">The username of the account to impersonate. This should be a valid
        /// SQL Server login. If the impersonation is successful, subsequent queries will be executed
        /// under the context of this user.</param>
        /// <remarks>
        /// This method first checks if the current user has the necessary permissions to impersonate
        /// another user using the CanImpersonate method. If the impersonation is possible, it executes
        /// the impersonation command. After attempting to impersonate, it queries the current system
        /// and database user context to confirm the impersonation status and provides appropriate
        /// feedback.
        ///
        /// If impersonation is not possible (due to insufficient permissions or an invalid username),
        /// an error message is displayed, and the connection's context remains unchanged.
        /// </remarks>
        public void Impersonate(SqlConnection con, string impersonate = null)
        {
            _print.Status($"Trying to impersonate '{impersonate}'", true);
            // Use the CanImpersonate method to check if the current user can impersonate the specified user.
            if (CanImpersonate(con, impersonate))
            {
                // Construct and execute the query with impersonation.
                string impersonationQuery = $"EXECUTE AS LOGIN = '{impersonate}';";
                string result = ExecuteQuery(con, impersonationQuery);

                if (result.ToLower().Contains("cannot execute as the server principal"))
                {
                    _print.Error("Cannot be impersonated.", true);
                }
                else
                {
                    _print.Success($"Impersonated server user '{ExecuteQuery(con, "SELECT SYSTEM_USER;")}'", true);
                    _print.Success($"Mapped to the username '{ExecuteQuery(con, "SELECT USER_NAME();")}'", true);
                }
            }
            else
            {
                _print.Error($"The {impersonate} login cannot be impersonated or you do not have sufficient privileges.", true);
            }
        }


        /// <summary>
        /// The ExecuteImpersonationCustomQuery method is used to execute
        /// a query against a SQL server using impersonation. Error handling
        /// is performed to ensure that the impersonated user exists before
        /// executing the query. This method expects that the output returns multiple lines.
        /// </summary>
        /// <param name="con">The SQL connection.</param>
        /// <param name="impersonate">The user to impersonate.</param>
        /// <param name="query">The SQL query to execute.</param>
        /// <returns>The query result or an error message.</returns>
        public string ExecuteImpersonationCustomQuery(SqlConnection con, string impersonate, string query)
        {
            // Use the CanImpersonate method to check if the current user can impersonate the specified user.
            if (CanImpersonate(con, impersonate))
            {
                // If the user can be impersonated, construct and execute the query with impersonation.
                string impersonationQuery = $"EXECUTE AS LOGIN = '{impersonate}'; {query}; REVERT;";
                return ExecuteCustomQuery(con, impersonationQuery);
            }
            else
            {
                // If the user cannot be impersonated, return an error.
                return _print.Error($"The {impersonate} login cannot be impersonated or you do not have sufficient privileges.");
            }
        }


        /// <summary>
        /// The ExecuteLinkedQuery method is used to execute a query against a 
        /// linked SQL server using openquery. This method expects that the output
        /// only returns one value on a single line and does not account for multi-line returns.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSQLServer"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteLinkedQuery(SqlConnection con, String linkedSQLServer, String query)
        {
            string sqlString = "";

            try
            {
                SqlCommand command = new("select * from openquery(\"" + linkedSQLServer + "\", '" + query + "')", con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    sqlString += reader[0];
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }

            return sqlString;
        }

        /// <summary>
        /// The ExecuteLinkedCustomQuery method is used to execute a query against a 
        /// linked SQL server using openquery. This method expects that the output
        /// returns multiple lines.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSQLServer"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteLinkedCustomQuery(SqlConnection con, string linkedSQLServer, string query)
        {
            string sqlString = "";

            try
            {
                SqlCommand command = new("select * from openquery(\"" + linkedSQLServer + "\", '" + query + "')", con);
                SqlDataReader reader = command.ExecuteReader();
                using (reader)
                {
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        int columnCount = 0;
                        // Print the column names.
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (reader.GetName(i).Equals(""))
                            {
                                // On some occasions, there may not be a column name returned, so we add one.
                                columnName = "column" + i.ToString() + " | ";
                            }
                            else
                            {
                                columnName = reader.GetName(i) + " | ";
                            }
                            sqlString += columnName;
                            hyphenCount += columnName.Length;
                            columnCount += 1;
                        }

                        sqlString += "\n";
                        sqlString += new String('-', hyphenCount);
                        sqlString += "\n";

                        // Retrieve data from the SQL data reader.
                        while (reader.Read())
                        {
                            // Apply formatting if there is more than one column.
                            if (columnCount <= 1)
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    sqlString += reader.GetValue(i) + " | " + "\n";
                                }
                            }
                            // Apply formatting if there is more than one column.
                            else
                            {

                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    if (i == (columnCount - 1))
                                    {
                                        sqlString += reader.GetValue(i) + " | \n";
                                    }
                                    else
                                    {
                                        sqlString += reader.GetValue(i) + " | ";
                                    }
                                }
                            }
                        }

                        // Remove the last few characters, wich consist of a space, pipe, space.
                        sqlString = sqlString.Remove(sqlString.Length - 2);
                    }
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }
            return sqlString;
        }



        /// <summary>
        /// The ExecuteLinkedCustomQueryRpcExec method is used to execute a
        /// query against a linked SQL server using 'EXECUTE (QUERY) AT HOSTNAME'.
        /// This is due to some stored procedures not returning accurate results
        /// when using openquery. This method expects that the output returns
        /// muliple lines.
        /// IMPORTANT: Any queries passed into this function need to have their 
        /// single quotes escaped. RPC needs to be enabled on the remote host.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteLinkedCustomQueryRpcExec(SqlConnection con, string linkedSqlServer, string query)
        {
            string sqlString = "";

            try
            {
                SqlCommand command = new("EXECUTE ('" + query + "') AT " + linkedSqlServer + ";", con);
                SqlDataReader reader = command.ExecuteReader();
                using (reader)
                {
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        int columnCount = 0;
                        // Print the column names.
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (reader.GetName(i).Equals(""))
                            {
                                // On some occasions, there may not be a column name returned, so we add one.
                                columnName = "column" + i.ToString() + " | ";
                            }
                            else
                            {
                                columnName = reader.GetName(i) + " | ";
                            }
                            sqlString += columnName;
                            hyphenCount += columnName.Length;
                            columnCount += 1;
                        }

                        sqlString += "\n";
                        sqlString += new String('-', hyphenCount);
                        sqlString += "\n";

                        // Retrieve data from the SQL data reader.
                        while (reader.Read())
                        {
                            // Apply formatting if there is more than one column.
                            if (columnCount <= 1)
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    sqlString += reader.GetValue(i) + " | " + "\n";
                                }
                            }
                            // Apply formatting if there is more than one column.
                            else
                            {

                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    if (i == (columnCount - 1))
                                    {
                                        sqlString += reader.GetValue(i) + " | \n";
                                    }
                                    else
                                    {
                                        sqlString += reader.GetValue(i) + " | ";
                                    }
                                }
                            }
                        }

                        // Remove the last few characters, wich consist of a space, pipe, space.
                        sqlString = sqlString.Remove(sqlString.Length - 2);
                    }
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }
            return sqlString;
        }

        /// <summary>
        /// Constructs a nested OPENQUERY statement for querying linked SQL servers in a chain.
        /// </summary>
        /// <param name="path">An array of server names representing the path of linked servers to traverse. 0 in front of them is mandatory to make the query work properly.</param>
        /// <param name="sql">The SQL query to be executed at the final server in the linked server path.</param>
        /// <param name="ticks">A counter used to double the single quotes for each level of nesting.</param>
        /// <returns>A string containing the nested OPENQUERY statement.</returns>
        /// <example>
        /// Calling GetSQLServerLinkQuery(new[] { "0", "a", "b", "c", "d" }, "SELECT * FROM SomeTable WHERE 'a'='a'") will produce:
        /// select * from openquery("a", 'select * from openquery("b", ''select * from openquery("c", ''''select * from openquery("d", ''''''SELECT * FROM SomeTable WHERE ''a''=''''a'''''''''')''')'')')
        /// </example>
        public static string GetSQLServerLinkQuery(string[] path, string sql, int ticks = 0)
        {
            if (path.Length <= 1)
            {
                // Base case: when there's only one server or none, just return the SQL with appropriately doubled quotes.
                return sql.Replace("'", new string('\'', (int)Math.Pow(2, ticks)));
            }
            else
            {
                var stringBuilder = new StringBuilder();
                stringBuilder.Append("select * from openquery(\"");
                stringBuilder.Append(path[1]);  // Taking the next server in the path.
                stringBuilder.Append("\", ");
                stringBuilder.Append(new string('\'', (int)Math.Pow(2, ticks)));

                // Recursively build the nested query for the rest of the path.
                string[] subPath = new string[path.Length - 1];
                Array.Copy(path, 1, subPath, 0, path.Length - 1);

                stringBuilder.Append(GetSQLServerLinkQuery(subPath, sql, ticks + 1)); // Recursive call with incremented ticks.
                stringBuilder.Append(new string('\'', (int)Math.Pow(2, ticks)));
                stringBuilder.Append(")");

                return stringBuilder.ToString();
            }
        }


        /// <summary>
        /// The ExecuteTunnelQuery method is used to execute a query against a chain of
        /// linked SQL servers using openquery. This method expects that the output
        /// only returns one value on a single line and does not account for multi-line returns.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="serverChain"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteTunnelQuery(SqlConnection con, string[] serverChain, string query)
        {
            string sqlString = "";

            try
            {
                string finalCommand = GetSQLServerLinkQuery(serverChain, query);
                SqlCommand command = new(finalCommand, con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    sqlString += reader[0];
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }

            return sqlString;
        }

        /// <summary>
        /// The ExecuteTunnelCustomQuery method is used to execute a query against a chain of
        /// linked SQL servers using openquery. This method expects that the output
        /// returns multiple lines.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="serverChain"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteTunnelCustomQuery(SqlConnection con, string[] serverChain, string query)
        {
            string sqlString = "";

            try
            {
                string finalCommand = GetSQLServerLinkQuery(serverChain, query);
                SqlCommand command = new(finalCommand, con);
                SqlDataReader reader = command.ExecuteReader();
                using (reader)
                {
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        int columnCount = 0;
                        // Print the column names.
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (reader.GetName(i).Equals(""))
                            {
                                // On some occasions, there may not be a column name returned, so we add one.
                                columnName = "column" + i.ToString() + " | ";
                            }
                            else
                            {
                                columnName = reader.GetName(i) + " | ";
                            }
                            sqlString += columnName;
                            hyphenCount += columnName.Length;
                            columnCount += 1;
                        }

                        sqlString += "\n";
                        sqlString += new String('-', hyphenCount);
                        sqlString += "\n";

                        // Retrieve data from the SQL data reader.
                        while (reader.Read())
                        {
                            // Apply formatting if there is more than one column.
                            if (columnCount <= 1)
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    sqlString += reader.GetValue(i) + " | " + "\n";
                                }
                            }
                            // Apply formatting if there is more than one column.
                            else
                            {

                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    if (i == (columnCount - 1))
                                    {
                                        sqlString += reader.GetValue(i) + " | \n";
                                    }
                                    else
                                    {
                                        sqlString += reader.GetValue(i) + " | ";
                                    }
                                }
                            }
                        }

                        // Remove the last few characters, wich consist of a space, pipe, space.
                        sqlString = sqlString.Remove(sqlString.Length - 2);
                    }
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.Errors[0].Message.ToString()));
            }
            catch (InvalidOperationException ex)
            {
                sqlString += _print.Error(string.Format("{0}.", ex.ToString()));
            }
            return sqlString;
        }


    }
}
