using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class ExecuteQuery
    {
        public ExecuteQuery(SqlConnection con, String query)
        {
            initialize(con, query);
        }
        // this simply takes a SQL query, executes it and prints to console
        public void initialize(SqlConnection con, String query)
        {
            try
            {
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                while (reader.Read() == true)
                {
                    Console.WriteLine(reader[0]);
                }
                Console.WriteLine("");
                reader.Close();
            }
            catch (SqlException ex)
            {
                Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
            }
            catch (InvalidOperationException)
            {
            }
        }
    }

    public class ExecuteCustomQuery
    {
        public ExecuteCustomQuery(SqlConnection con, String query)
        {
            initialize(con, query);
        }
        public void initialize(SqlConnection con, String query)
        {
            try
            {
                SqlCommand command = new SqlCommand(query, con);
                Console.WriteLine("");
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    
                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        // print the column names
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            columnName = reader.GetName(i) + " | ";
                            Console.Write(columnName);
                            hyphenCount += columnName.Length;
                        }
                        Console.WriteLine("");
                        Console.WriteLine(new String('-', hyphenCount));

                        while (reader.Read())
                        {
                            // get data
                            for (int i = 0; i < reader.FieldCount; i++)
                            {
                                Console.Write(reader.GetValue(i) + " | ");

                            }
                            Console.WriteLine("");
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
            }
            catch (InvalidOperationException)
            {
            }
            
        }
    }

    public class ExecuteLinkedQuery
    {
        public ExecuteLinkedQuery(SqlConnection con, String linkedSQLServer, String query)
        {
            initialize(con, linkedSQLServer, query);
        }
        // this simply takes a SQL query, executes it on a linked server and prints to console
        public void initialize(SqlConnection con, String linkedSQLServer, String query)
        {
            try
            {
                SqlCommand command = new SqlCommand("select * from openquery(\"" + linkedSQLServer + "\", '" + query + "')", con);
                Console.WriteLine("");
                using (SqlDataReader reader = command.ExecuteReader())
                {

                    if (reader.HasRows)
                    {
                        int hyphenCount = 0;
                        string columnName = "";
                        // print the column names
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            columnName = reader.GetName(i) + " | ";
                            Console.Write(columnName);
                            hyphenCount += columnName.Length;
                        }
                        Console.WriteLine("");
                        Console.WriteLine(new String('-', hyphenCount));

                        while (reader.Read())
                        {
                            // get data
                            for (int i = 0; i < reader.FieldCount; i++)
                            {
                                Console.Write(reader.GetValue(i) + " | ");

                            }
                            Console.WriteLine("");
                        }
                    }
                }

            }
            catch (SqlException ex)
            {
                Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
            }
            catch (InvalidOperationException)
            {
            }
        }
    }

    public class SearchKeyword
    {
        public SearchKeyword(SqlConnection con, String query)
        {
            initialize(con, query);
        }
        // this searches a database for column names which match a supplied seeach term
        public void initialize(SqlConnection con, String query)
        {
            try
            {
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                Console.WriteLine("");
                while (reader.Read() == true)
                {
                    Console.WriteLine("Table name: " + reader[0]);
                    Console.WriteLine("Column name: " + reader[1]);
                }
                Console.WriteLine("");
                reader.Close();
            }
            catch (SqlException ex)
            {
                Console.WriteLine("\n[!] ERROR: " + ex.Errors[0].Message.ToString() + "\n");
            }
            catch (InvalidOperationException)
            {
            }
        }
    }
}
