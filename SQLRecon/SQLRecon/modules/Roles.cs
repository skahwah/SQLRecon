using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Roles
    {
        /// <summary>
        /// The StandardOrImpersonation module obtains database user and Windows principals
        /// from a remote SQL server. Roles are also obtained.
        /// Impersonation is supported. 
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        internal static void StandardOrImpersonation(SqlConnection con, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "system_user", Query.SystemUser },
                { "user_name", Query.UserName },
                { "roles", Query.Roles },
                { "server_permissions", string.Format(Query.GetPermissions, "SERVER") },
                { "database_permissions", string.Format(Query.GetPermissions, "DATABASE") }
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }
            
            Print.Status($"Logged in as {Sql.Query(con, queries["system_user"])}", true);
            Print.Status($"Mapped to the user {Sql.Query(con, queries["user_name"])}", true);

            Console.WriteLine();
            Print.Status("Server Permissions:", true);
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(con, queries["server_permissions"]));
            Console.WriteLine();
            
            Print.Status("Database Permissions:", true);
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(con, queries["database_permissions"]));
            Console.WriteLine();
            
            Print.Status("Database Roles:", true);
            
            // This SQL command can be run by low privilege users and extracts all
            // the observable roles which are present in the current database
            // "select name from sys.database_principals where type = 'R'" also works.
            string getRoles = Sql.CustomQuery(con, queries["roles"]);
            
            List<string> rolesList = Print.ExtractColumnValues(getRoles, "name");
            
            // These are the default MS SQL database roles.
            string[] defaultRoles =
            {
                "sysadmin", "setupadmin", "serveradmin", "securityadmin",
                "processadmin", "diskadmin", "dbcreator", "bulkadmin"
            };
            
            // Combine all observable roles with the default roles.
            string[] combinedRoles = rolesList.Concat(defaultRoles).ToArray();

            Dictionary<string, string> roleMembership = new Dictionary<string, string>();
            
            // Test to see if the current principal is a member of any roles.
            foreach (string role in combinedRoles)
            {
                bool result = (string.IsNullOrEmpty(impersonate))
                    ? CheckRoleMembership(con, role.Trim())
                    : CheckRoleMembership(con, role.Trim(), impersonate);
                
                if (result)
                {
                    roleMembership[role] = "Yes";
                }
                else
                {
                    roleMembership[role] = "No";
                }
            }
            Console.WriteLine();
            Console.WriteLine(Print.ConvertDictionaryToMarkdownTable(roleMembership, "Role", "Membership"));
        }

        /// <summary>
        /// The LinkedOrChain module obtained database user and Windows principals from a Linked
        /// SQL server. Roles are also obtained.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        internal static void LinkedOrChain(SqlConnection con, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "system_user", Query.SystemUser },
                { "user_name", Query.UserName },
                { "roles", Query.Roles },
                { "server_permissions", string.Format(Query.GetPermissions, "SERVER") },
                { "database_permissions", string.Format(Query.GetPermissions, "DATABASE") }
            };

            queries = (linkedSqlServerChain == null) 
                // Format all queries so that they are compatible for execution on a linked SQL server.
                ? Format.LinkedDictionary(linkedSqlServer, queries)
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                : Format.LinkedChainDictionary(linkedSqlServerChain, queries);
            
            Print.Status($"Logged in as {Sql.Query(con, queries["system_user"])}", true);
            Print.Status($"Mapped to the user {Sql.Query(con, queries["user_name"])}", true);

            Console.WriteLine();
            Print.Status("Server Permissions:", true);
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(con, queries["server_permissions"]));
            Console.WriteLine();
            
            Print.Status("Database Permissions:", true);
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(con, queries["database_permissions"]));
            Console.WriteLine();
            
            Print.Status("Database Roles:", true);
            
            // This SQL command can be run by low privilege users and extracts all
            // the observable roles which are present in the current database
            // "select name from sys.database_principals where type = 'R'" also works.
            string getRoles = Sql.CustomQuery(con, queries["roles"]);

            List<string> rolesList = Print.ExtractColumnValues(getRoles, "name");
            
            // These are the default MS SQL database roles.
            string[] defaultRoles = { "sysadmin", "setupadmin", "serveradmin",
                    "securityadmin", "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            // Combine all observable roles with the default roles.
            string[] combinedRoles = rolesList.Concat(defaultRoles).ToArray();

            Dictionary<string, string> roleMembership = new Dictionary<string, string>();
            
            // Test to see if the current principal is a member of any roles.
            foreach (string role in combinedRoles)
            {
                bool result  = CheckLinkedRoleMembership(con, role.Trim(), linkedSqlServer);
                
                if (result)
                {
                    roleMembership[role] = "Yes";
                }
                else
                {
                    roleMembership[role] = "No";
                }
            }
            Console.WriteLine();
            Console.WriteLine(Print.ConvertDictionaryToMarkdownTable(roleMembership, "Role", "Membership"));
        }

        /// <summary>
        /// The CheckServerRole method checks if a user is part of a role.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="impersonate"></param>
        /// <returns></returns>
        internal static bool CheckRoleMembership(SqlConnection con, string role, string impersonate = null)
        {
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            string query = !string.IsNullOrEmpty(impersonate) 
                ? Format.ImpersonationQuery(impersonate, string.Format(Query.CheckRole, role)) 
                : string.Format(Query.CheckRole, role);
            
            return Sql.Query(con, query).TrimStart('\n').Equals("1");
        }

        /// <summary>
        /// The CheckImpersonation method is responsible for determining if a supplied
        /// user can be impersonated.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        internal static bool CheckImpersonation(SqlConnection con, string user)
        {
            user = user.Replace("'", "''");
            
            // Check if a specific user can be impersonated
            return Sql.Query(con,string.Format(Query.CheckImpersonation, user)).Equals("1");
        }

        /// <summary>
        /// The CheckLinkedServerRole method checks if a user is part of a role on a linked SQL server.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="role"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        /// <returns></returns>
        internal static bool CheckLinkedRoleMembership(SqlConnection con, string role, string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // Format the query, so it is compatible for execution on a linked SQL server.
            string query = (linkedSqlServerChain == null) 
                ? Format.LinkedQuery(linkedSqlServer, string.Format(Query.CheckRole, role)) 
                // Format the query, so it is compatible for execution on the last SQL server specified in a linked chain.
                : Format.LinkedChainQuery(linkedSqlServerChain, string.Format(Query.CheckRole, role));
            
            return Sql.Query(con, query).TrimStart('\n').Equals("1");
        }
    }
}