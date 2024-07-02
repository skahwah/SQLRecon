using System;
using System.Reflection;
using SQLRecon.Modules;
using SQLRecon.Utilities;

namespace SQLRecon.Commands
{
    internal abstract class SccmModules
    {
        /// <summary>
        /// The ExecuteModule method will match the user supplied module in the
        /// Var.Module variable against a method name and use reflection to execute
        /// the method in the local class.
        /// </summary>
        internal static void Execute()
        {
            // First check to see if there is a SQL connection object. However, if the
            // /debug flag is preset, then SQL connection object is not necessary.
            if (Var.Connect == null && Var.Debug == false)
            {
                // Go no further
                return;
            }

            /*
             * Next, check to see what the execution context is. This can be standard, impersonation, linked, or chained.
             * Based on this, several things can happen:
             *
             * 1. If the context is "standard", no checks need to be performed.
             * 2. If the context is "impersonation", check to see if the user can be impersonated. Otherwise, gracefully exit.
             */

            if (_determineContext(Var.Context) == false) return;

            // Reference: https://t.ly/rTjmp
            // Set the type name to this local class.
            Type type = Type.GetType(MethodBase.GetCurrentMethod().DeclaringType.ToString());

            if (type != null)
            {
                // Match the method name to the module that has been supplied as an argument.
                MethodInfo method = type.GetMethod(Var.SccmModule);

                if (method != null)
                {
                    // Call the method.
                    method.Invoke(null, null);
                }
                else
                {
                    // Go no further.
                    Print.Error($"'{Var.SccmModule}' is an invalid SCCM module.", true);
                }
            }
        }

        /// <summary>
        /// The addsccmadmin method will elevate the specified account to a 'Full Administrator'
        /// within SCCM. If target user is already an SCCM user, this module will instead add necessary
        /// privileges to elevate. This module require sysadmin or similar privileges as writing to 
        /// SCCM database tables is required.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void addadmin()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.AddAdmin(Var.Context) == false) return;

            Sccm.AddSccmAdmin(Var.Connect, Var.Arg1, Var.Arg2, Var.Impersonate);
        }

        /// <summary>
        /// The credentials method lists credentials vaulted by SCCM for
        /// use in various functions. These credentials can not be remotely decrypted
        /// as the key is stored on the SCCM server. However, this module provides
        /// intel on if it makes sense to attempt to obtain the key.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void credentials()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.Impersonation(Var.Context) == false) return;
            
            Sccm.Credentials(Var.Connect, Var.Impersonate);
        }

        /// <summary>
        /// The decryptcredentials method recovers encrypted credential string
        /// for accounts vaulted in SCCM and attempts to use the Microsoft Systems Management Server CSP 
        /// to attempt to decrypt them to plaintext. Uses the logic from @XPN's initial PoC SCCM secret decryption gist:
        /// Reference: https://t.ly/Dlinv
        /// This function must be run from an SCCM management server in a context
        /// that has the ability to access this CSP (high-integrity admin or SYSTEM).
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void decryptcredentials()
        {
            Sccm.DecryptCredentials(Var.Connect);
        }

        /// <summary>
        /// The logons method queries the 'Computer_System_DATA' table to 
        /// retrieve all associated SCCM clients along with the user that last logged into them.
        /// NOTE: This only updates once a week by default and will not be 100% up to date.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void logons()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.Impersonation(Var.Context) == false) return;
            
            // Optional filter argument
            if (Var.ParsedArguments.ContainsKey("filter") && !string.IsNullOrEmpty(Var.ParsedArguments["filter"]))
            {
                Var.Arg1 = Var.ParsedArguments["filter"];
            }
            else
            {
                Var.Arg1 = null;
            }
            
            Sccm.Logons(Var.Connect, Var.Arg1, Var.Impersonate);
        }

        /// <summary>
        /// The RemoveSCCMAdmin method removes the privileges of a user by removing a user
        /// entirely from the SCCM database. Use the arguments provided by output of the 
        /// AddSCCMAdmin command to run this command. This module require sysadmin or 
        /// similar privileges as writing to SCCM database tables is required.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void removeadmin()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.RemoveAdmin(Var.Context) == false) return;
            
            Sccm.RemoveSccmAdmin(Var.Connect, Var.Arg1, Var.Arg2, Var.Impersonate);

        }

        /// <summary>
        /// The sites method lists all sites stored in the SCCM databases' 'DPInfo' table.
        /// This can provide additional attack avenues as different sites 
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void sites()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.Impersonation(Var.Context) == false) return;
            
            Sccm.Sites(Var.Connect, Var.Impersonate);
        }

        /// <summary>
        /// The taskdata method recovers all task sequences stored in the SCCM
        /// database and decrypts them to plaintext.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void taskdata()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.Impersonation(Var.Context) == false) return;
            
            Sccm.TaskData(Var.Connect, Var.Impersonate);
        }

        /// <summary>
        /// The tasklist method provides a list of all task sequences stored
        /// in the SCCM database, but does not access the actual task data contents.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void tasklist()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.Impersonation(Var.Context) == false) return;
            
            Sccm.TaskList(Var.Connect, Var.Impersonate);
        }

        /// <summary>
        /// The users method lists all users in the RBAC_Admins table.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void users()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSccmArguments.Impersonation(Var.Context) == false) return;
            
            Sccm.Users(Var.Connect, Var.Impersonate);
        }

        /// <summary>
        /// The _determineContext method will determine if a user supplied for impersonation
        /// can be impersonated before progressing onwards to execute modules in the context
        /// of impersonation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private static bool _determineContext(string context)
        {
            if (Var.Debug)
            {
                // If the /debug flag is present, return true and skip impersonation
                // and linked SQL server checks.
                return true;
            }
            else
            {
                switch (context)
                {
                    case "standard":
                        return true;
                    case "impersonation":
                        // Check to see if the supplied user can be impersonated.
                        if (Roles.CheckImpersonation(Var.Connect, Var.Impersonate))
                        {
                            return true;
                        }
                        else
                        {
                            // Go no further
                            Print.Error($"'{Var.Impersonate}' can not be impersonated on {Var.SqlServer}.", true);
                            return false;
                        }
                    default:
                        Print.Error($"'{Var.Context}' is not a valid context.", true);
                        return false;
                }
            }
        }
    }

    /// <summary>
    /// The CheckSccmArguments class validates arguments which are required for modules.
    /// </summary>
    internal abstract class CheckSccmArguments
    {
        /// <summary>
        /// Required arguments for the addadmin module
        /// Checks performed for standard and impersonation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool AddAdmin(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("user") && !string.IsNullOrEmpty(Var.ParsedArguments["user"]) &&
                        Var.ParsedArguments.ContainsKey("sid") && !string.IsNullOrEmpty(Var.ParsedArguments["sid"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["user"];

                        Var.Arg2 = Var.ParsedArguments["sid"].ToLower().Equals("current") 
                            ? "" 
                            : Var.ParsedArguments["sid"];
                        
                        return true;
                    }
                    else
                    {
                        Print.Error("Use '/user:current /sid:current' if you want to set 'Full Administrator' privileges " +
                                    "on the current user account. Or use '/user:DOMAIN\\USERNAME /sid:SID' to set 'Full Administrator' " +
                                    "privileges on a target account.", true);
                        // Go no further.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("user") && !string.IsNullOrEmpty(Var.ParsedArguments["user"]) &&
                        Var.ParsedArguments.ContainsKey("sid") && !string.IsNullOrEmpty(Var.ParsedArguments["sid"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["user"];

                        Var.Arg2 = Var.ParsedArguments["sid"].ToLower().Equals("current") 
                            ? "" 
                            : Var.ParsedArguments["sid"];
                        
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:). Use '/user:current /sid:current' if " +
                                    "you want to set 'Full Administrator' privileges " +
                                    "on the current user account. Or use '/user:DOMAIN\\USERNAME /sid:SID' to set 'Full Administrator' " +
                                    "privileges on a target account.", true);
                        // Go no further.
                        return false;
                    }
                default:
                    Print.Error($"'{context}' is not a valid context.", true);
                    // Go no further. Gracefully exit.
                    return false;
            }
        }
        
        /// <summary>
        /// Required arguments for any module supporting impersonation with no arguments.
        /// Checks performed for standard and impersonation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Impersonation(string context)
        {
            switch (context)
            {
                case "standard":
                    return true;
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                default:
                    Print.Error($"'{context}' is not a valid context.", true);
                    // Go no further. Gracefully exit.
                    return false;
            }
        }

        /// <summary>
        /// Required arguments for the removeadmin module
        /// Checks performed for standard and impersonation.
        /// </summary>
        /// <param name="context"></param>
        internal static bool RemoveAdmin(string context)
        {

            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("user") && !string.IsNullOrEmpty(Var.ParsedArguments["user"]) &&
                        Var.ParsedArguments.ContainsKey("remove") && !string.IsNullOrEmpty(Var.ParsedArguments["remove"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["user"];
                        Var.Arg2 = Var.ParsedArguments["remove"];
                        return true;
                    }
                    else
                    {
                        Print.Error(
                            "Must include AdminID (/user:) and permissions string (/remove:) to remove 'Full Administrator' privileges from the target account.",
                            true);
                        // Go no further.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("user") && !string.IsNullOrEmpty(Var.ParsedArguments["user"]) &&
                        Var.ParsedArguments.ContainsKey("remove") && !string.IsNullOrEmpty(Var.ParsedArguments["remove"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["user"];
                        Var.Arg2 = Var.ParsedArguments["remove"];
                        return true;
                    }
                    else
                    {
                        Print.Error(
                            "Must supply a user to impersonate (/i:, /iuser:), AdminID (/user:) and permissions string (/remove:) " +
                            "to remove 'Full Administrator' privileges from the target account.", true);
                        // Go no further.
                        return false;
                    }
                default:
                    Print.Error($"'{context}' is not a valid context.", true);
                    // Go no further. Gracefully exit.
                    return false;
            }
        }
    }
}