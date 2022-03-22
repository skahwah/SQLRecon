using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using SQLRecon.Modules;

namespace SQLRecon.Auth
{
    public class ArgumentLogic
    {
        //variables used for command line arguments and general program execution
        private static SqlConnection con = null;
        private static String authType = "";
        private static String sqlServer = "";
        private static String database = "";
        private static String domain = "";
        private static String user = "";
        private static String pass = "";
        private static String module = "";
        private static String option = "";
        private static String linkedSqlServer = "";
        private static String impersonate = "";

        public void AuthenticationType(Dictionary<string, string> argDict)
        {
            // if authentication type is not given, display help and return
            if (!argDict.ContainsKey("a"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply an authentication type (-a Windows, -a Local or -a Azure)");
                return;
            }

            // if the authentication type is Windows, make sure that sql server, database and module has been set
            if (argDict["a"].ToLower().Equals("windows") && argDict.ContainsKey("s") && argDict.ContainsKey("d") && argDict.ContainsKey("m"))
            {
                authType = argDict["a"].ToLower();
                sqlServer = argDict["s"].ToLower();
                database = argDict["d"].ToLower();
                WindowsAuth WindowsAuth = new WindowsAuth();
                con = WindowsAuth.Send(sqlServer, database);
                EvaluateTheArguments(argDict);
            }
            else if (argDict["a"].ToLower().Equals("windows"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SQL server (-s), database (-d) and module (-m)");
                return;
            }

            /* if authentication type is local, make sure that:
                - the SQL server
                - database
                - username 
                - and password has been given, otherwise display help and return
            */
            if (argDict["a"].ToLower().Equals("local") && argDict.ContainsKey("s") && argDict.ContainsKey("d") && argDict.ContainsKey("u") && argDict.ContainsKey("p") && argDict.ContainsKey("m"))
            {
                authType = argDict["a"].ToLower();
                sqlServer = argDict["s"].ToLower();
                database = argDict["d"].ToLower();
                user = argDict["u"];
                pass = argDict["p"];
                LocalAuth LocalAuth = new LocalAuth();
                con = LocalAuth.Send(sqlServer, database, user, pass);
                EvaluateTheArguments(argDict); 
            }
            else if (argDict["a"].ToLower().Equals("local"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SQL server (-s), database (-d), username (-u), password (-p) and module (-m)");
                return;
            }

            /* if authentication type is azure, make sure that:
                - the SQL server
                - database
                - username 
                - domain
                - and password has been given, otherwise display help and return
            */
            if (argDict["a"].ToLower().Equals("azure") && argDict.ContainsKey("s") && argDict.ContainsKey("d") && argDict.ContainsKey("r") && argDict.ContainsKey("u") && argDict.ContainsKey("p") && argDict.ContainsKey("m"))
            {
                if (!argDict["r"].Contains("."))
                {
                    Console.WriteLine("\n[!] ERROR: Domain (-r) must be the fully qualified domain name (domain.com)");
                    return;
                }
                else
                {
                    authType = argDict["a"].ToLower();
                    sqlServer = argDict["s"].ToLower();
                    database = argDict["d"].ToLower();
                    domain = argDict["r"];
                    user = argDict["u"];
                    pass = argDict["p"];
                    AzureAuth AzureAuth = new AzureAuth();
                    con = AzureAuth.Send(sqlServer, database, domain, user, pass);
                    EvaluateTheArguments(argDict);
                }
            }
            else if (argDict["a"].ToLower().Equals("azure"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SQL server (-s), database (-d), domain (-r), username (-u), password (-p) and module (-m)");
                return;
            }
        }

        // EvaluateTheArguments
        public static void EvaluateTheArguments(Dictionary<string, string> argDict)
        {
            // standard single sql server logic
            // if the module type is query, then set the module to query and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("query") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a query (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("smb") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SMB path (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("xpcmd") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a command (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("olecmd") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a command (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("search") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a keyword (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict.ContainsKey("o"))
            {
                module = argDict["m"].ToLower();
                option = argDict["o"];
            }
            else
            {
                module = argDict["m"].ToLower();
            }

            // linked queries logic
            // if the module type is lquery, then set the linkedSqlServer, set the module to lquery and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("lquery"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and query (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ltables"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and database on the linked SQL server (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lsmb"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and SMB path (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldatabases"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lwhoami"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lroles"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else
            {
                module = argDict["m"].ToLower();
            }

            // impersonation queries logic
            // if the module type is impersonate, then set the sqlServer, set the module to impersonate and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("iquery"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and query (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ixpcmd"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ienablexp"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("idisablexp"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("iolecmd"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ienableole"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("idisableole"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else
            {
                module = argDict["m"].ToLower();
            }

            // this is effectively a huge module switch


            // ##########################################
            // ########## standard sql modules ##########
            // ##########################################
            // if the module type is querylogin, then execute the querylogin sql query
            if (module.Equals("whoami"))
            {
                Console.Out.WriteLine("\n[+] Logged in as: ");
                ExecuteQuery ExecuteQuery = new ExecuteQuery(con, "SELECT SYSTEM_USER;");
            }
            // if the module type is mapped, then execute the mapped sql query
            else if (module.Equals("mapped"))
            {
                Console.Out.WriteLine("\n[+] Mapped to the user: ");
                ExecuteQuery ExecuteQuery = new ExecuteQuery(con, "SELECT USER_NAME();");
            }
            // if the module type is roles, then execute the roles module
            else if (module.Equals("roles"))
            {
                Console.Out.WriteLine("\n[+] Enumerating roles: ");
                Roles Roles = new Roles();

                Roles.Public(con);
                Roles.SysAdmin(con);
            }
            else if (module.Equals("databases"))
            {
                Console.Out.WriteLine("\n[+] Databases: ");
                ExecuteQuery ExecuteQuery = new ExecuteQuery(con, "SELECT name FROM master.dbo.sysdatabases;");
            }
            else if (module.Equals("tables"))
            {
                Console.Out.WriteLine("\n[+] Tables in " + database + ":");
                ExecuteQuery ExecuteQuery = new ExecuteQuery(con, "SELECT CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) FROM " + database + ".INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';");
            }
            // if the module type is query, then excute the ExecuteQuery module with the supplied sql query
            else if (module.Equals("query"))
            {
                Console.Out.WriteLine("\n[+] Executing: " + option);
                ExecuteCustomQuery ExecuteCustomQuery = new ExecuteCustomQuery(con, option);
            }
            else if (module.Equals("search"))
            {
                Console.Out.WriteLine("\n[+] Searching for columns containing " + option + " in " + database);
                SearchKeyword SearchKeyword = new SearchKeyword(con, "select table_name, column_name from INFORMATION_SCHEMA.COLUMNS where column_name like '%" + option + "%';");
            }
            // if the module type is smb, then excute the CaptureHash module with the supplied smb share
            else if (module.Equals("smb"))
            {
                Console.Out.WriteLine("\n[+] Sending SMB Request to: " + option);
                CaptureHash CaptureHash = new CaptureHash(con, option);
            }
            // if the module type is impersonate, then excute the impersonate module
            else if (module.Equals("impersonate"))
            {
                Console.Out.WriteLine("\n[+] Enumerating accounts that can be impersonated: ");
                EnumImpersonation EnumImpersonation = new EnumImpersonation(con);
            }
            // if the module type is enablexp, then excute the XPCmdShell module and enable xp_cmdshell
            else if (module.Equals("enablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell on: " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.Enable(con);
            }
            // if the module type is enablexp, then excute the XPCmdShell module and disable xp_cmdshell
            else if (module.Equals("disablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell on: " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.Disable(con);
            }
            // if the module type is xpcmd, then excute the XPCmdShell.Command module with the supplied command
            else if (module.Equals("xpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " on " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.Command(con, option);
            }
            // if the module type is enableole, then excute the OLE module and enable Ole Automation Procedures
            else if (module.Equals("enableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling Ole Automation Procedures on: " + sqlServer);
                OLE Ole = new OLE();
                Ole.Enable(con);
            }
            // if the module type is disableole, then excute the OLE module and disable Ole Automation Procedures
            else if (module.Equals("disableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling Ole Automation Procedures on: " + sqlServer);
                OLE Ole = new OLE();
                Ole.Disable(con);
            }
            // if the module type is olecmd, then excute the OLE.Command module with the supplied command
            else if (module.Equals("olecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " on " + sqlServer);
                OLE Ole = new OLE();
                Ole.Command(con, option);
            }
            // if the module type is enableclr, then excute the CLR module and enable CLR integration
            else if (module.Equals("enableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR integration on: " + sqlServer);
                CLR clr = new CLR();
                clr.Enable(con);
            }
            // if the module type is disableclr, then excute the CLR module and disable CLR integration
            else if (module.Equals("disableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR integration on: " + sqlServer);
                CLR clr = new CLR();
                clr.Disable(con);
            }

            // if the module type is links, then excute the ExecuteQuery module with the supplied sql query
            else if (module.Equals("links"))
            {
                Console.Out.WriteLine("\n[+] Additional Links: ");
                ExecuteQuery ExecuteQuery = new ExecuteQuery(con, "EXEC ('sp_linkedservers');");
            }

            // ########################################
            // ########## linked sql modules ##########
            // ########################################
            else if (module.Equals("ldatabases"))
            {
                Console.Out.WriteLine("\n[+] Databases on " + linkedSqlServer + " via " + sqlServer);
                option = "select name from sys.databases;";
                ExecuteLinkedQuery ExecuteCustomLinkedQuery = new ExecuteLinkedQuery(con, linkedSqlServer, option);
            }
            else if (module.Equals("ltables"))
            {
                Console.Out.WriteLine("\n[+] Tables in database " + database + " on " + linkedSqlServer + " via " + sqlServer);
                option = "select * from " + option + ".INFORMATION_SCHEMA.TABLES;";
                ExecuteLinkedQuery ExecuteCustomLinkedQuery = new ExecuteLinkedQuery(con, linkedSqlServer, option);
            }
            else if (module.Equals("lquery"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " on " + linkedSqlServer + " via " + sqlServer);
                ExecuteLinkedQuery ExecuteCustomLinkedQuery = new ExecuteLinkedQuery(con, linkedSqlServer, option);
            }
            else if (module.Equals("lsmb"))
            {
                Console.Out.WriteLine("\n[+] Sending SMB Request from " + linkedSqlServer + " to " + option + " via " + sqlServer);
                CaptureLinkedHash CaptureLinkedHash = new CaptureLinkedHash(con, linkedSqlServer, option);
            }
            else if (module.Equals("lwhoami"))
            {
                Console.Out.WriteLine("\n[+] Executing 'SELECT SYSTEM_USER' on " + linkedSqlServer + " via " + sqlServer);

                Console.Out.WriteLine("\n[+] Logged in as: ");
                ExecuteLinkedQuery ExecuteCustomLinkedQuery = new ExecuteLinkedQuery(con, linkedSqlServer, "SELECT SYSTEM_USER;");
            }
            else if (module.Equals("lroles"))
            {
                Console.Out.WriteLine("\n[+] Enumerating roles on " + linkedSqlServer + " via " + sqlServer);

                LinkedRoles LinkedRoles = new LinkedRoles();

                LinkedRoles.LinkedPublic(con, linkedSqlServer);
                LinkedRoles.LinkedSysAdmin(con, linkedSqlServer);
            }

            // ###############################################
            // ########## impersonation sql modules ##########
            // ###############################################
            else if (module.Equals("iquery"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " as " + impersonate + " on " + sqlServer);
                ExecuteCustomQuery ExecuteCustomQuery = new ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate +"'; " + option);
            }
            // if the module type is enablexp, then excute the XPCmdShell module and enable xp_cmdshell
            else if (module.Equals("ienablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell as " + impersonate + " on " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.Enable(con, impersonate);
            }
            // if the module type is enablexp, then excute the XPCmdShell module and disable xp_cmdshell
            else if (module.Equals("idisablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell as " + impersonate + " on " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.Disable(con, impersonate);
            }
            // if the module type is xpcmd, then excute the XPCmdShell.Command module with the supplied command
            else if (module.Equals("ixpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " as " + impersonate + " on " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.Command(con, option, impersonate);
            }
            // if the module type is enableole, then excute the OLE module and enable Ole Automation Procedures
            else if (module.Equals("ienableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling Ole Automation Procedures as " + impersonate + " on " + sqlServer);
                OLE Ole = new OLE();
                Ole.Enable(con, impersonate);
            }
            // if the module type is disableole, then excute the OLE module and disable Ole Automation Procedures
            else if (module.Equals("idisableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling Ole Automation Procedures as " + impersonate + " on " + sqlServer);
                OLE Ole = new OLE();
                Ole.Disable(con, impersonate);
            }
            // if the module type is olecmd, then excute the OLE.Command module with the supplied command
            else if (module.Equals("iolecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " as " + impersonate + " on " + sqlServer);
                OLE Ole = new OLE();
                Ole.Command(con, option, impersonate);
            }

            else
            {
                Console.WriteLine("[!] ERROR: Module " + module + " does not exist\n");
            }
            
        } // end EvaluateTheArguments
    }
}
