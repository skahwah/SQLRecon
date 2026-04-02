using System;
using System.Data.SqlClient;
using System.Text;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Sql
    {
        /// <summary>
        /// The NonQuery method is used to execute a statement against a SQL server
        /// that does not return a result set (e.g. CREATE PROCEDURE, EXECUTE AS LOGIN).
        /// This is required for PTH auth because the SqlConnection passed to modules
        /// is a dummy sentinel mapped to a PTHTdsConnection via PthState.Unwrap().
        /// </summary>
        /// <param name="con"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        internal static string NonQuery(SqlConnection con, string query)
        {
            if (Var.Verbose)
            {
                Print.Debug("Query:");
                Print.Nested(query, true);
            }

            if (Var.Debug)
            {
                Print.Debug("Query:");
                Print.Nested(query, true);
                return "";
            }

            var _pthConn = PthState.Unwrap(con);
            if (_pthConn != null)
            {
                _pthConn.ExecuteNonQuery(query);
                return "";
            }

            try
            {
                SqlCommand command = new(query, con);
                command.ExecuteNonQuery();
            }
            catch (SqlException ex)
            {
                return Print.Error($"{ex.Errors[0].Message}.");
            }
            catch (InvalidOperationException ex)
            {
                return Print.Error($"{ex}.");
            }

            return "";
        }

        /// <summary>
        /// The Query method is used to execute a query against a SQL
        /// server. This method expects that the output only returns one value
        /// on a single line and does not account for multi-line returns.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        internal static string Query(SqlConnection con, string query)
        {
            // If the verbose flag is present, then the query will still execute on the SQL server
            // and print the SQL query to console.
            if (Var.Verbose)
            {
                Print.Debug("Query:");
                Print.Nested(query, true);
            }

            // If the debug flag is present, then the query will not execute on the SQL server
            // and print the SQL query to console.
            if (Var.Debug)
            {
                Print.Debug("Query:");
                Print.Nested(query, true);
                return "";
            }

            // PTH auth: look up the PTHTdsConnection for this sentinel so that multiple
            // independent PTH connections can coexist (e.g. ADSI module).
            var _pthConn = PthState.Unwrap(con);
            if (_pthConn != null)
                return _pthConn.ExecuteQuery(query);

            string sqlString = "";

            try
            {
                SqlCommand command = new(query, con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    sqlString += reader[0];
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += Print.Error($"{ex.Errors[0].Message}.");
            }
            catch (InvalidOperationException ex)
            {
                sqlString += Print.Error($"{ex}.");
            }

            return sqlString;
        }

        /// <summary>
        /// The CustomQuery method is used to execute a query against a SQL
        /// server. This method expects that the output returns multiple lines.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        internal static string CustomQuery(SqlConnection con, string query)
        {
            // If the verbose flag is present, then the query will still execute on the SQL server
            // and print the SQL query to console.
            if (Var.Verbose)
            {
                Print.Debug("Query:");
                Print.Nested(query, true);
            }

            // If the debug flag is present, then the query will not execute on the SQL server
            // and print the SQL query to console.
            if (Var.Debug)
            {
                Print.Debug("Query:");
                Print.Nested(query, true);
                return "";
            }

            // PTH auth: look up the PTHTdsConnection for this sentinel.
            var _pthConn = PthState.Unwrap(con);
            if (_pthConn != null)
                return _pthConn.ExecuteCustomQuery(query);

            StringBuilder sqlStringBuilder = new();
            
            try
            {
                SqlCommand command = new(query, con);
                SqlDataReader reader = command.ExecuteReader();

                using (reader)
                {
                    sqlStringBuilder.Append(Print.ConvertSqlDataReaderToMarkdownTable(reader));
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlStringBuilder.Append(Print.Error($"{ex.Errors[0].Message}"));
            }
            catch (InvalidOperationException ex)
            {
                sqlStringBuilder.Append(Print.Error(ex.ToString()));
            }
            return sqlStringBuilder.ToString();
        }
    }
}
