using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
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
                // Log the query being executed
                _print.Debug($"Executing following SQL query: {query}");

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
        /// Converts the data from a SqlDataReader into a Markdown-friendly table format.
        /// </summary>
        /// <param name="reader">The SqlDataReader containing the query results.</param>
        /// <returns>A string containing the results formatted as a Markdown table.</returns>
        private string ConvertToMarkdownTable(SqlDataReader reader)
        {
            StringBuilder sqlStringBuilder = new StringBuilder();
            List<int> columnWidths = new List<int>();
            List<string[]> rows = new List<string[]>();

            if (reader.HasRows)
            {
                int columnCount = reader.FieldCount;

                // Initialize column widths with header lengths
                for (int i = 0; i < columnCount; i++)
                {
                    columnWidths.Add(reader.GetName(i).Length);
                }

                // Read data and calculate column widths
                while (reader.Read())
                {
                    string[] row = new string[columnCount];
                    for (int i = 0; i < columnCount; i++)
                    {
                        string cellValue = reader.GetValue(i).ToString();
                        row[i] = cellValue;
                        columnWidths[i] = Math.Max(columnWidths[i], cellValue.Length);
                    }
                    rows.Add(row);
                }

                // Ensure column names are checked for width after data read
                for (int i = 0; i < columnCount; i++)
                {
                    string columnName = reader.GetName(i).Equals("") ? "column" + i.ToString() : reader.GetName(i);
                    columnWidths[i] = Math.Max(columnWidths[i], columnName.Length);
                }

                // Print the column names
                for (int i = 0; i < columnCount; i++)
                {
                    string columnName = reader.GetName(i).Equals("") ? "column" + i.ToString() : reader.GetName(i);
                    sqlStringBuilder.Append("| ").Append(columnName.PadRight(columnWidths[i])).Append(" ");
                }
                sqlStringBuilder.AppendLine("|");

                // Print the markdown separator
                for (int i = 0; i < columnCount; i++)
                {
                    sqlStringBuilder.Append("| ").Append(new string('-', columnWidths[i])).Append(" ");
                }
                sqlStringBuilder.AppendLine("|");

                // Print the data rows
                foreach (var row in rows)
                {
                    for (int i = 0; i < columnCount; i++)
                    {
                        sqlStringBuilder.Append("| ").Append(row[i].PadRight(columnWidths[i])).Append(" ");
                    }
                    sqlStringBuilder.AppendLine("|");
                }
            }

            return sqlStringBuilder.ToString();
        }


        /// <summary>
        /// Parses the query result and returns a list of values for the specified column.
        /// </summary>
        /// <param name="queryResult">The result of the SQL query as a string.</param>
        /// <param name="columnName">The name of the column to extract values from.</param>
        /// <returns>A list of values for the specified column.</returns>
        public List<string> ExtractColumnValues(string queryResult, string columnName)
        {
            if (string.IsNullOrWhiteSpace(queryResult))
            {
                return new List<string>();
            }

            var lines = queryResult.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 2)
            {
                return new List<string>();
            }

            var headers = lines[0].Split('|', (char)StringSplitOptions.RemoveEmptyEntries)
                                .Select(h => h.Trim())
                                .ToList();
            int columnIndex = headers.IndexOf(columnName);
            if (columnIndex == -1)
            {
                return new List<string>();
            }

            return lines.Skip(2) // Skip the header and separator lines
                        .Select(line => line.Split('|', (char)StringSplitOptions.RemoveEmptyEntries))
                        .Where(columns => columns.Length > columnIndex)
                        .Select(columns => columns[columnIndex].Trim())
                        .ToList();
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
            StringBuilder sqlStringBuilder = new();

            try
            {
                // Log the query being executed
                _print.Debug($"Executing following SQL query: {query}");

                // Execute the main query
                SqlCommand command = new(query, con);
                SqlDataReader reader = command.ExecuteReader();

                using (reader)
                {
                    sqlStringBuilder.Append(ConvertToMarkdownTable(reader));
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlStringBuilder.Append(_print.Error($"{ex.Errors[0].Message}"));
            }
            catch (InvalidOperationException ex)
            {
                sqlStringBuilder.Append(_print.Error(ex.ToString()));
            }
            return sqlStringBuilder.ToString();
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
        /// Checks if the current user can impersonate another user in a tunnel of linked SQL Servers.
        /// </summary>
        /// <param name="con">The SQL connection to use for executing the check.</param>
        /// <param name="impersonate">The username of the user to check impersonation permissions for.</param>
        /// <param name="tunnelSqlServers">The chain of linked SQL servers.</param>
        /// <returns>True if the current user can impersonate the specified user in the tunnel of servers, false otherwise.</returns>
        public bool CanImpersonateTunnel(SqlConnection con, string impersonate, string[] tunnelSqlServers)
        {
            // Check if the current user is a sysadmin in the last server in the tunnel
            string sysAdminCheckQuery = $"SELECT IS_SRVROLEMEMBER('sysadmin');";
            string isSysAdmin = ExecuteTunnelCustomQuery(con, tunnelSqlServers, sysAdminCheckQuery).Trim();

            if (isSysAdmin.Contains("1"))
            {
                return true;
            }

            // Check if the specific user can be impersonated in the last server in the tunnel
            string impersonateCheckQuery = $"SELECT 1 FROM sys.server_permissions a " +
                                           $"INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id " +
                                           $"WHERE a.permission_name = 'IMPERSONATE' AND b.name = '{impersonate.Replace("'", "''")}'";

            string impersonateCheckResult = ExecuteTunnelCustomQuery(con, tunnelSqlServers, impersonateCheckQuery).Trim();

            // If any result is returned, the user can be impersonated
            return impersonateCheckResult.Contains("1");
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
                    _print.Nested($"Mapped to the username '{ExecuteQuery(con, "SELECT USER_NAME();")}'", true);
                }
            }
            else
            {
                _print.Error($"The {impersonate} login cannot be impersonated or you do not have sufficient privileges.", true);
            }
        }

        /// <summary>
        /// Constructs a nested OPENQUERY statement for querying linked SQL servers in a chain.
        /// </summary>
        /// <param name="path">An array of server names representing the path of linked servers to traverse. '0' in front of them is mandatory to make the query work properly.</param>
        /// <param name="sql">The SQL query to be executed at the final server in the linked server path.</param>
        /// <param name="ticks">A counter used to double the single quotes for each level of nesting.</param>
        /// <returns>A string containing the nested OPENQUERY statement.</returns>
        /// <example>
        /// Calling GetNestedOpenQueryForLinkedServers(new[] { "0", "a", "b", "c", "d" }, "SELECT * FROM SomeTable WHERE 'a'='a'") will produce:
        /// select * from openquery("a", 'select * from openquery("b", ''select * from openquery("c", ''''select * from openquery("d", ''''''SELECT * FROM SomeTable WHERE ''a''=''''a'''''''''')''')'')')
        /// </example>
        public static string GetNestedOpenQueryForLinkedServers(string[] path, string sql, int ticks = 0)

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

                stringBuilder.Append(GetNestedOpenQueryForLinkedServers(subPath, sql, ticks + 1)); // Recursive call with incremented ticks.
                stringBuilder.Append(new string('\'', (int)Math.Pow(2, ticks)));
                stringBuilder.Append(")");

                string result = stringBuilder.ToString();
                return result;
            }
        }

        /// <summary>
        /// The method dynamically builds the nested SQL command based on the number of servers listed in the serverChain.
        /// It constructs the query by iterating over the server list from the end towards the beginning (after skipping the "0" index).
        /// Each server in the chain adds another layer of EXEC ('...') AT [ServerName] around the existing query.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="sql"></param>
        /// <returns></returns>
        public static string GetSQLServerRpcConfigQuery(string[] path, string sql)
        {
            string currentQuery = sql;

            // Start from the end of the array and skip the first element ("0")
            for (int i = path.Length - 1; i > 0; i--)
            {
                string server = path[i];
                // Double single quotes to escape them in the SQL string
                currentQuery = $"EXEC ('{currentQuery.Replace("'", "''")}') AT {server}";
            }

            return currentQuery;
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
                string finalCommand = GetNestedOpenQueryForLinkedServers(serverChain, query);
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

        public string ExecuteTunnelQuery(SqlConnection con, string server, string query)
        {
            // Constructs the server chain array with "0" as the first element and the provided server as the second
            string[] serverChain = new string[] { "0", server };
            string sqlString = "";

            try
            {
                string finalCommand = GetNestedOpenQueryForLinkedServers(serverChain, query);
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
        /// Executes a custom query that is sent through a tunnel of linked SQL servers specified as an array.
        /// </summary>
        /// <param name="con">The SQL connection to use for executing the query.</param>
        /// <param name="serverChain">An array of server names representing the path of linked servers to traverse.</param>
        /// <param name="query">The SQL query to be executed at the final server in the linked server path.</param>
        /// <returns>A string containing the results of the executed query.</returns>
        public string ExecuteTunnelCustomQuery(SqlConnection con, string[] serverChain, string query)
        {
            return ExecuteCustomQuery(con, GetNestedOpenQueryForLinkedServers(serverChain, query));
        }

        /// <summary>
        /// Executes a custom query that is sent through a tunnel of linked SQL servers specified as a single string.
        /// </summary>
        /// <param name="con">The SQL connection to use for executing the query.</param>
        /// <param name="serverChain">A single server name representing the path of a linked server to traverse.</param>
        /// <param name="query">The SQL query to be executed at the final server in the linked server path.</param>
        /// <returns>A string containing the results of the executed query.</returns>
        public string ExecuteTunnelCustomQuery(SqlConnection con, string server, string query)
        {
            // Constructs the server chain array with "0" as the first element and the provided server as the second
            string[] serverChain = new string[] { "0", server };
            return ExecuteCustomQuery(con, GetNestedOpenQueryForLinkedServers(serverChain, query));
        }

        public string ExecuteTunnelCustomQueryRpcExec(SqlConnection con, string[] serverChain, string query)
        {
            return ExecuteCustomQuery(con, GetSQLServerRpcConfigQuery(serverChain, query));
        }

        public string ExecuteTunnelCustomQueryRpcExec(SqlConnection con, string server, string query)
        {
            // Constructs the server chain array with "0" as the first element and the provided server as the second
            string[] serverChain = new string[] { "0", server };
            return ExecuteCustomQuery(con, GetSQLServerRpcConfigQuery(serverChain, query));
        }



    }
}
