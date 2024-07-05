using System;
using System.Collections.Generic;
using System.Text;

namespace SQLRecon.Utilities
{
    internal abstract class Format
    {
        /// <summary>
        /// The ImpersonationDictionary method adds the EXECUTE AS LOGIN statement along with
        /// the user to impersonate in front of every standard SQL query supplied
        /// in a dictionary.
        /// </summary>
        /// <param name="impersonate"></param>
        /// <param name="dict"></param>
        /// <returns></returns>
        internal static Dictionary<string, string> ImpersonationDictionary(string impersonate, Dictionary<string, string> dict)
        {
            Dictionary<string, string> queries = new Dictionary<string, string>(dict.Count);

            foreach (KeyValuePair<string, string> entry in dict)
            {
                queries[entry.Key] = ImpersonationQuery(impersonate, entry.Value);
            }

            dict.Clear();

            return queries;
        }

        /// <summary>
        /// The LinkedDictionary method adds the OPENQUERY statement along with the linked SQL server
        /// to connect to and the SQL query in front of every standard SQL query supplied
        /// in a dictionary.
        /// Intelligence exists to determine whether the dictionary key starts with 'rpc_'. If it does,
        /// the SQL query will not have the OPENQUERY statement prepended, but the EXEC query instead and the linked SQL
        /// server will be placed at the end of the query.
        /// </summary>
        /// <param name="linkedSqlServer"></param>
        /// <param name="dict"></param>
        /// <returns></returns>
        internal static Dictionary<string, string> LinkedDictionary(string linkedSqlServer, Dictionary<string, string> dict)
        {
            Dictionary<string, string> queries = new Dictionary<string, string>(dict.Count);

            foreach (KeyValuePair<string, string> entry in dict)
            {
                if (entry.Key.StartsWith("rpc_"))
                {
                    queries[entry.Key] = LinkedQuery(linkedSqlServer, entry.Value, true);
                }
                else
                {
                    queries[entry.Key] = LinkedQuery(linkedSqlServer, entry.Value);
                }
            }

            dict.Clear();

            return queries;
        }

        /// <summary>
        /// The LinkedChainDictionary takes a standard SQL query and prepares it with multiple
        /// OPENQUERY statements dynamically so that it can be used in a chain, until finally executed on
        /// a target SQL server.
        /// Intelligence exists to determine whether the dictionary key starts with 'rpc_'. If it does,
        /// the SQL query will not have the OPENQUERY statement prepended, but the EXEC query instead and the linked SQL
        /// server will be placed at the end of the query.
        /// </summary>
        /// <param name="linkedSqlServerChain"></param>
        /// <param name="dict"></param>
        /// <returns></returns>
        internal static Dictionary<string, string> LinkedChainDictionary(string[] linkedSqlServerChain, Dictionary<string, string> dict)
        {
            Dictionary<string, string> queries = new Dictionary<string, string>(dict.Count);

            foreach (KeyValuePair<string, string> entry in dict)
            {
                if (entry.Key.StartsWith("rpc_"))
                {
                    queries[entry.Key] = _linkedChainRpcQuery(linkedSqlServerChain, entry.Value);
                }
                else
                {
                    queries[entry.Key] = LinkedChainQuery(linkedSqlServerChain, entry.Value);
                }
            }

            dict.Clear();

            return queries;
        }

        /// <summary>
        /// The ImpersonationQuery method adds the EXECUTE AS LOGIN statement along with
        /// the user to impersonate in front of every standard SQL query
        /// </summary>
        /// <param name="impersonate"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        internal static string ImpersonationQuery(string impersonate, string query)
        {
            return "EXECUTE AS LOGIN = '" + impersonate + "'; " + query;
        }

        /// <summary>
        /// The LinkedQuery method adds the OPENQUERY statement along with the linked SQL server
        /// to connect to and the SQL query in front of every standard SQL query supplied.
        /// The optional argument of 'rpc' is available. If selected, the SQL query will not have the OPENQUERY
        /// statement prepended, but the EXEC query instead and the linked SQL
        /// server will be placed at the end of the query.
        /// </summary>
        /// <param name="linkedSqlServer"></param>
        /// <param name="query"></param>
        /// <param name="rpc"></param>
        /// <returns></returns>
        internal static string LinkedQuery(string linkedSqlServer, string query, bool rpc = false)
        {
            query = query.Replace("'", "''");

            return (rpc == false)
                ? "SELECT * FROM OPENQUERY(\"" + linkedSqlServer + "\", '" + query + "')"
                : "EXECUTE ('" + query + "') AT " + linkedSqlServer + ";";
        }

        /// <summary>
        /// The LinkedChainQuery method constructs a nested OPENQUERY statement for querying linked SQL servers in a chain.
        /// Credit to Azaël MARTIN (n3rada).
        /// </summary>
        /// <param name="linkedSqlServerChain">An array of server names representing the path of linked servers to traverse. '0' in front of them is mandatory to make the query work properly.</param>
        /// <param name="query">The SQL query to be executed at the final server in the linked server path.</param>
        /// <param name="ticks">A counter used to double the single quotes for each level of nesting.</param>
        /// <returns>A string containing the nested OPENQUERY statement.</returns>
        /// <example>
        /// Calling GetNestedOpenQueryForLinkedServers(new[] { "0", "a", "b", "c", "d" }, "SELECT * FROM SomeTable WHERE 'a'='a'") will produce:
        /// select * from openquery("a", 'select * from openquery("b", ''select * from openquery("c", ''''select * from openquery("d", ''''''SELECT * FROM SomeTable WHERE ''a''=''''a'''''''''')''')'')')
        /// </example>
        internal static string LinkedChainQuery(string[] linkedSqlServerChain, string query, int ticks = 0)
        {
            if (linkedSqlServerChain.Length <= 1)
            {
                // Base case: when there's only one server or none, just return the SQL with appropriately doubled quotes.
                return query.Replace("'", new string('\'', (int)Math.Pow(2, ticks)));
            }

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append("SELECT * FROM OPENQUERY(\"");
            stringBuilder.Append(linkedSqlServerChain[1]);
            // Taking the next server in the path.
            stringBuilder.Append("\", ");
            stringBuilder.Append(new string('\'', (int)Math.Pow(2, ticks)));

            // Recursively build the nested query for the rest of the path.
            string[] subPath = new string[linkedSqlServerChain.Length - 1];
            Array.Copy(linkedSqlServerChain, 1, subPath, 0, linkedSqlServerChain.Length - 1);

            stringBuilder.Append(LinkedChainQuery(subPath, query, ticks + 1));
            // Recursive call with incremented ticks.
            stringBuilder.Append(new string('\'', (int)Math.Pow(2, ticks)));
            stringBuilder.Append(")");

            return stringBuilder.ToString();
        }

        /// <summary>
        /// The LinkedChainRpcQuery method constructs a nested EXEC AT statement for querying linked SQL servers in a chain.
        /// Credit to Azaël MARTIN (n3rada).
        /// </summary>
        /// <param name="linkedSqlServerChain"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        private static string _linkedChainRpcQuery(string[] linkedSqlServerChain, string query)
        {
            string currentQuery = query;

            // Start from the end of the array and skip the first element ("0")
            for (int i = linkedSqlServerChain.Length - 1; i > 0; i--)
            {
                string server = linkedSqlServerChain[i];
                // Double single quotes to escape them in the SQL string
                currentQuery = $"EXEC ('{currentQuery.Replace("'", "''")}') AT {server}";
            }

            return currentQuery;
        }
    }
}