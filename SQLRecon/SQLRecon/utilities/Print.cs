using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using SQLRecon.Commands;

namespace SQLRecon.Utilities
{
    internal abstract class Print
    {
        /// <summary>
        /// The ConvertDictionaryToMarkdownTable table converts the data from a dictionary
        /// into a Markdown-friendly table format.
        /// </summary>
        /// <param name="dictionary"></param>
        /// <param name="columnOneHeader"></param>
        /// <param name="columnTwoHeader"></param>
        /// <returns></returns>
        internal static string ConvertDictionaryToMarkdownTable(Dictionary<string, string> dictionary, string columnOneHeader, string columnTwoHeader)
        {
            StringBuilder sqlStringBuilder = new StringBuilder();

            if (dictionary.Count > 0)
            {
                /*
                 * Take the headers and add them to the end of the dictionary
                 * This is done for formatting reasons as the next step is to get the
                 * length of the longest string in the dictionary, and it is possible
                 * that a column name is longer than any values.
                 */
                dictionary.Add(columnOneHeader,columnTwoHeader);

                // Obtain the length of the longest key name and base the width of the first column off this.
                int columnOneWidth = dictionary.Max(t => t.Key.Length);
                sqlStringBuilder.Append("| ").Append(columnOneHeader.PadRight(columnOneWidth)).Append(" ");

                // Obtain the length of the longest value name and base the width of the second column off this.
                int columnTwoWidth = dictionary.Max(t => t.Value.Length);
                sqlStringBuilder.Append("| ").Append(columnTwoHeader.PadRight(columnTwoWidth)).Append(" ");

                // New line
                sqlStringBuilder.AppendLine("|");

                // Print the markdown separator for both columns
                sqlStringBuilder.Append("| ").Append(new string('-', columnOneWidth)).Append(" ");
                sqlStringBuilder.Append("| ").Append(new string('-', columnTwoWidth)).Append(" ");

                // New line
                sqlStringBuilder.AppendLine("|");

                // Iterate over the dictionary and place the values into rows for the Markdown table
                // Ignore the last entry as it is just the column names.
                for (int i = 0; i < dictionary.Count - 1; i++)
                {
                    KeyValuePair<string, string> item = dictionary.ElementAt(i);
                    sqlStringBuilder.Append("| ").Append(item.Key.PadRight(columnOneWidth)).Append(" ");
                    sqlStringBuilder.Append("| ").Append(item.Value.PadRight(columnTwoWidth)).Append(" ");
                    sqlStringBuilder.AppendLine("|");
                }
            }
            return sqlStringBuilder.ToString();
        }

        /// <summary>
        /// The ConvertSqlDataReaderToMarkdownTable table converts the data from a SqlDataReader
        /// into a Markdown-friendly table format.
        /// Credit to Azaël MARTIN (n3rada).
        /// </summary>
        /// <param name="reader">The SqlDataReader containing the query results.</param>
        /// <returns>A string containing the results formatted as a Markdown table.</returns>
        internal static string ConvertSqlDataReaderToMarkdownTable(SqlDataReader reader)
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
                foreach (string[] row in rows)
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
        /// The Debug method adds a debug message to the beginning
        /// of a provided string. This method prints by default.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <returns></returns>
        internal static void Debug(string sqlOutput)
        {
            if (Var.Debug && Var.Verbose)
            {
                Console.WriteLine($"[VERBOSE] {sqlOutput}");
            }
            else if (Var.Debug)
            {
                Console.WriteLine($"[DEBUG] {sqlOutput}");
            }
            else if (Var.Verbose)
            {
                Console.WriteLine($"[VERBOSE] {sqlOutput}");
            }
            else
            {
                Console.WriteLine($"[-] {sqlOutput}");
            }
        }

        /// <summary>
        /// The DebugQueries method is used to print a dictionary consisting of
        /// SQL queries. The method returns a boolean value which enables logic to be
        /// in place to gracefully exit the program, or continue with execution.
        /// </summary>
        /// <param name="queries"></param>
        /// <returns></returns>
        internal static bool DebugQueries(Dictionary<string, string> queries)
        {
            if (Var.Debug)
            {
                Debug($"SQL queries used for this module:");

                foreach (KeyValuePair<string, string> q in queries)
                {
                    Nested($"{q.Key} -> {q.Value}", true);
                }

                return true;
            }
            else
            {
                return false;
            }

        }

        /// <summary>
        /// The Error method adds an error message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        internal static string Error(string sqlOutput, bool print = false)
        {
            if (print)
            {
                Console.WriteLine($"[X] {sqlOutput}");
                return "";
            }
            else
            {
                return $"[X] {sqlOutput}";
            }
        }

        /// <summary>
        /// The ExtractColumnValues method parses the result of a SQL query,
        /// and returns a list of values for a specified column.
        /// Credit to Azaël MARTIN (n3rada).
        /// </summary>
        /// <param name="queryResult">The result of the SQL query as a string.</param>
        /// <param name="columnName">The name of the column to extract values from.</param>
        /// <returns>A list of values for the specified column.</returns>
        internal static List<string> ExtractColumnValues(string queryResult, string columnName)
        {
            if (string.IsNullOrWhiteSpace(queryResult))
            {
                return new List<string>();
            }

            string[] lines = queryResult.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 2)
            {
                return new List<string>();
            }

            List<string> headers = lines[0].Split('|', (char)StringSplitOptions.RemoveEmptyEntries)
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
        /// The IsOutputEmpty method checks to see if a string is empty
        /// or null before providing a generic message.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        internal static string IsOutputEmpty(string sqlOutput, bool print = false)
        {
            if (print)
            {
                Console.WriteLine((string.IsNullOrWhiteSpace(sqlOutput))
                    ? "[+] No results."
                    : sqlOutput);
                return "";
            }
            else
            {
                return (string.IsNullOrWhiteSpace(sqlOutput))
                    ? "[+] No results."
                    : sqlOutput;
            }
        }

        /// <summary>
        /// The Nested method adds an arrow to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        internal static string Nested(string sqlOutput, bool print = false)
        {
            if (print)
            {
                Console.WriteLine($" |-> {sqlOutput}");
                return "";
            }
            else
            {
                return $" |-> {sqlOutput}";
            }
        }

        /// <summary>
        /// The Status method adds a status indicator to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        internal static string Status(string sqlOutput, bool print = false)
        {
            if (print)
            {
                Console.WriteLine($"[*] {sqlOutput}");
                return "";
            }
            else
            {
                return $"[*] {sqlOutput}";
            }
        }

        /// <summary>
        /// The Success method adds a success message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        internal static string Success(string sqlOutput, bool print = false)
        {
            if (print)
            {
                Console.WriteLine($"[+] {sqlOutput}");
                return "";
            }
            else
            {
                return $"[+] {sqlOutput}";
            }
        }

        /// <summary>
        /// The Warning method adds a warning message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        internal static string Warning(string sqlOutput, bool print = false)
        {
            if (print)
            {
                Console.WriteLine($"[!] WARNING: {sqlOutput}");
                return "";
            }
            else
            {
                return $"[!] WARNING: {sqlOutput}";
            }
        }
    }
}
