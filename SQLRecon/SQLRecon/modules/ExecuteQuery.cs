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
