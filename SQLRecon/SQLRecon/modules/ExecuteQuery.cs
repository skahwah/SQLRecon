using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class SQLQuery
    {
        // Use this if the output is expected to just have 1 value to return
        public string ExecuteQuery(SqlConnection con, String query)
        {
            string sqlString = "\n";

            try
            {
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    sqlString += reader[0];
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += "[!] ERROR: " + ex.Errors[0].Message.ToString();
            }
            catch (InvalidOperationException)
            {
            }

            return sqlString;
        }

        // Use this if the output is expected to just have over 1 item, row, column, etc
        public string ExecuteCustomQuery(SqlConnection con, String query)
        {
            string sqlString = "\n\n";

            try
            {
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                using (reader)
                {
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        int columnCount = 0;
                        // print the column names
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (reader.GetName(i).Equals(""))
                            {
                                // on occasion, there may not be a column name returned, so we add one.
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

                        // get data
                        while (reader.Read())
                        {
                            // formatting if there is only 1 column
                            if (columnCount <= 1)
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    sqlString += reader.GetValue(i) + " | " + "\n";
                                }
                            }
                            // formatting if there is more than 1 column
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

                        // remove the last space pipe space.
                        sqlString = sqlString.Remove(sqlString.Length - 2);
                    }
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += ex.Errors[0].Message.ToString();
            }
            catch (InvalidOperationException)
            {
            }
            return sqlString;
        }

        public string ExecuteLinkedQuery(SqlConnection con, String linkedSQLServer, String query)
        {
            string sqlString = "\n";

            try
            {
                SqlCommand command = new SqlCommand("select * from openquery(\"" + linkedSQLServer + "\", '" + query + "')", con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    sqlString += reader[0];
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += "[!] ERROR: " + ex.Errors[0].Message.ToString();
            }
            catch (InvalidOperationException)
            {
            }

            return sqlString;
        }

        public string ExecuteLinkedCustomQuery(SqlConnection con, String linkedSQLServer, String query)
        {
            string sqlString = "\n\n";

            try
            {
                SqlCommand command = new SqlCommand("select * from openquery(\"" + linkedSQLServer + "\", '" + query + "')", con);
                SqlDataReader reader = command.ExecuteReader();
                using (reader)
                {
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        int columnCount = 0;
                        // print the column names
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (reader.GetName(i).Equals(""))
                            {
                                // on occasion, there may not be a column name returned, so we add one.
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

                        // get data
                        while (reader.Read())
                        {
                            // formatting if there is only 1 column
                            if (columnCount <= 1)
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    sqlString += reader.GetValue(i) + " | " + "\n";
                                }
                            }
                            // formatting if there is more than 1 column
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

                        // remove the last space pipe space.
                        sqlString = sqlString.Remove(sqlString.Length - 2);
                    }
                }
                reader.Close();
            }
            catch (SqlException ex)
            {
                sqlString += ex.Errors[0].Message.ToString();
            }
            catch (InvalidOperationException)
            {
            }
            return sqlString;
        }
    }
}
