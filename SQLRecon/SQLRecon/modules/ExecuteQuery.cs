using System;
using System.Data.SqlClient;
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
        /// The ExecuteImpersonationQuery method is used to execute
        /// a query against a SQL server using impersonation. Error handling
        /// is performed to ensure that the impersonated user exists before
        /// executing the query.
        /// This method expects that the output only returns one value
        /// on a single line and does not account for multi-line returns.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteImpersonationQuery(SqlConnection con, string impersonate, string query)
        {
            string sqlString = ExecuteCustomQuery(con,
                "SELECT distinct b.name FROM sys.server_permissions a " +
                "INNER JOIN sys.server_principals b ON a.grantor_principal_id " +
                "= b.principal_id WHERE a.permission_name = 'IMPERSONATE';");

            // Check to see if the supplied user can be impersonated.
            if (sqlString.ToLower().Contains(impersonate.ToLower()))
            {
                // Prepend the query with EXECUTE AS LOGIN and the impersonated user.
                sqlString = ExecuteQuery(con,
                    "EXECUTE AS LOGIN = '" + impersonate + "';" + query);

                return (sqlString.ToLower().Contains("cannot execute as the server principal"))
                    ? _print.Error(string.Format("The {0} login can not be impersonated.", impersonate))
                    : sqlString;
            }
            else
            {
                // Go no further
                return _print.Error(string.Format("The {0} login can not be impersonated.", impersonate));
            }
        }

        /// <summary>
        /// The ExecuteCustomImpersonationQuery method is used to execute
        /// a query against a SQL server using impersonation. Error handling
        /// is performed to ensure that the impersonated user exists before
        /// executing the query.
        /// This method expects that the output returns multiple lines.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public string ExecuteImpersonationCustomQuery(SqlConnection con, string impersonate, string query)
        {
            string sqlString = ExecuteCustomQuery(con,
                "SELECT distinct b.name FROM sys.server_permissions a " +
                "INNER JOIN sys.server_principals b ON a.grantor_principal_id " +
                "= b.principal_id WHERE a.permission_name = 'IMPERSONATE';");

            // Check to see if the supplied user can be impersonated.
            if (sqlString.ToLower().Contains(impersonate.ToLower()))
            {
                // Prepend the query with EXECUTE AS LOGIN and the impersonated user.
                sqlString =  ExecuteCustomQuery(con, 
                    "EXECUTE AS LOGIN = '" + impersonate + "';" + query);

                return (sqlString.ToLower().Contains("cannot execute as the server principal"))
                    ? _print.Error(string.Format("The {0} login can not be impersonated.", impersonate))
                    : sqlString;
            }
            else
            {
                // Go no further
                return _print.Error(string.Format("The {0} login can not be impersonated.", impersonate));
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
    }
}
