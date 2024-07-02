using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using SQLRecon.Modules;
using SQLRecon.Utilities;

namespace SQLRecon.Commands
{
    /// <summary>
    /// The SqlModules class is responsible for executing SQL modules.
    /// </summary>
    internal abstract class SqlModules
    {
        private static string _query;

        /// <summary>
        /// The ExecuteModule method will match the user supplied module in the
        /// Var.Module variable against a method name and use reflection to execute
        /// the method in the local class.
        /// </summary>
        internal static void Execute()
        {
            /*
             * First check to see if there is a SQL connection object.
             * However, if the /debug flag is preset, then SQL connection object is not necessary.
             * If there is no valid connection object, then gracefully exit.
             */

            if (Var.Connect == null && Var.Debug == false) return;

            /*
             * Next, check to see what the execution context is. This can be standard, impersonation, linked, or chained.
             * Based on this, several things can happen:
             *
             * 1. If the context is "standard", no checks need to be performed.
             * 2. If the context is "impersonation", check to see if the user can be impersonated. Otherwise, gracefully exit.
             * 3. If the context is "linked" or "chain", check to see if the first linked server exists. Otherwise, gracefully exit.
             */

            if (_determineContext(Var.Context) == false) return;

            // Reference: https://t.ly/rTjmp
            // Set the type name to this local class.
            Type type = Type.GetType(MethodBase.GetCurrentMethod().DeclaringType.ToString());

            // If the type name can not be set to the class name, then gracefully exit.
            if (type == null) return;

            // Match the method name to the module that has been supplied as an argument.
            MethodInfo method = type.GetMethod(Var.Module);

            if (method != null)
            {
                // Call the method.
                method.Invoke(null, null);
            }
            else
            {
                // Gracefully exit
                Print.Error($"'{Var.Module}' is an invalid SQL module.", true);
            }
        }

        /// <summary>
        /// The adsi method is used against SQL server to obtain cleartext ADSI credentials.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void adsi()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.Adsi(Var.Context) == false) return;

            Print.Status($"Obtaining ADSI credentials for '{Var.Arg1}'", true);
            Console.WriteLine();
            
            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    Adsi.StandardOrImpersonation(Var.Connect, Var.Arg1, Var.Arg2, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    Adsi.LinkedOrChain(Var.Connect, Var.Arg1, Var.Arg2, Var.LinkedSqlServer, Var.SqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }

        /// <summary>
        /// The agentcmd method is used execute system commands via agent jobs.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void agentcmd()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.AgentCmd(Var.Context) == false) return;
            
            // Check for optional /subsystem argument
            if (Var.ParsedArguments.ContainsKey("subsystem") && !string.IsNullOrEmpty(Var.ParsedArguments["subsystem"]))
            {
                // PowerShell or CmdExec are the two most relevant SQL agent job subsystems
                // https://t.ly/2nl9f
                string[] validSubsystems = { "powershell", "cmdexec" };

                if (validSubsystems.Contains(Var.ParsedArguments["subsystem"].ToLower()))
                {
                    Var.Arg1 = Var.ParsedArguments["subsystem"].ToLower();
                }
                else
                {
                    Print.Error($"'{Var.Arg1}' is not a valid subsystem that be be used with SQL agent jobs.", true);
                }
            }
            else
            {
                Var.Arg1 = "powershell";
            }
            
            Print.Status($"Executing '{Var.Arg2}' using the '{Var.Arg1}' subsystem.", true);
            Console.WriteLine();
            
            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    AgentJobs.StandardOrImpersonation(Var.Connect, Var.SqlServer, Var.Arg1, Var.Arg2, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    AgentJobs.LinkedOrChain(Var.Connect, Var.LinkedSqlServer, Var.Arg1, Var.Arg2, Var.SqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }

        /// <summary>
        /// The agentstatus method checks to see if SQL server agent is running.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void agentstatus()
        {
            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    AgentJobs.GetAgentStatusAndJobs(Var.Connect, Var.SqlServer, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    AgentJobs.GetLinkedAgentStatusAndJobs(Var.Connect, Var.LinkedSqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }

        /// <summary>
        /// The checkrpc method is used against the initial SQL server to
        /// identify what systems can have RPC enabled.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void checkrpc()
        {
            Print.Status("The following SQL servers can have RPC configured.", true);
            
            switch(Var.Context) 
            { 
                case "standard": 
                    _query = Query.IsRpcEnabled;
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, Query.IsRpcEnabled);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, Query.IsRpcEnabled);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, Query.IsRpcEnabled);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            } 
            
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(Var.Connect, _query));
        }

        /// <summary>
        /// The clr method is used to load and execute a custom .NET CLR assembly on a SQL server.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void clr()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.Clr(Var.Context) == false) return;

            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    Clr.StandardOrImpersonation(Var.Connect, Var.Arg1, Var.Arg2, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    Clr.LinkedOrChain(Var.Connect, Var.Arg1, Var.Arg2, Var.LinkedSqlServer, Var.SqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }

        /// <summary>
        /// The columns method list the columns for a table in a database.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.      
        /// </summary>
        public static void columns()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.ColumnsOrRows(Var.Context) == false) return;
            
            // Check if RPC is enabled for linked or chained contexts
            if (_checkLinkedRpc(Var.Context) == false) return;
            
            Print.Status($"Displaying columns from '{Var.Arg1}' in '{Var.Arg2}'", true);
            
            _query = string.Format(Query.GetColumns, Var.Arg1, Var.Arg2);

            switch(Var.Context) 
            { 
                case "standard": 
                    _query = string.Format(Query.GetColumns, Var.Arg1, Var.Arg2);
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, _query);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, _query, true);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, string.Format(Query.GetLinkedChainColumns, Var.Arg1));
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }

            _query = Sql.CustomQuery(Var.Connect, _query);

                
            if (string.IsNullOrEmpty(_query))
            {
                Console.WriteLine();
                Print.Error($"No results. If the '{Var.Arg1}' database and '{Var.Arg2}' table exist, " +
                             "then this is likely a permissions issue.", true);
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(_query);
            }
        }

        /// <summary>
        /// The databases method shows all configured databases on a SQL server.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void databases()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    _query = Query.GetDatabases;
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, Query.GetDatabases);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, Query.GetDatabases);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, Query.GetDatabases);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(Var.Connect, _query));
        }

        /// <summary>
        /// The disableclr method is used against SQL server to disable CLR integration.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disableclr()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "clr enabled", "0", Var.SqlServer);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "clr enabled", "0", Var.SqlServer, Var.Impersonate);
                    break;
                case "linked":
                    Config.LinkedModuleToggle(Var.Connect, "clr enabled", "0", Var.LinkedSqlServer, Var.SqlServer);
                    break;
                case "chained":
                    Config.LinkedChainModuleToggle(Var.Connect, "clr enabled", "0", Var.LinkedSqlServersChain, Var.SqlServer);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The disableole method is used against SQL server to disable OLE automation.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disableole()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "Ole Automation Procedures", "0", Var.SqlServer);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "Ole Automation Procedures", "0", Var.SqlServer, Var.Impersonate);
                    break;
                case "linked":
                    Config.LinkedModuleToggle(Var.Connect, "Ole Automation Procedures", "0", Var.LinkedSqlServer, Var.SqlServer);
                    break;
                case "chained":
                    Config.LinkedChainModuleToggle(Var.Connect, "Ole Automation Procedures", "0", Var.LinkedSqlServersChain, Var.SqlServer);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The disablerpc method is used against SQL server to disable 'rpc out' on a specified SQL server.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disablerpc()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.DisableOrEnableRpc(Var.Context) == false) return;

            Print.Status($"Disabling RPC on {Var.Arg1}", true);
            Console.WriteLine();
            
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "rpc", "false", Var.Arg1);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "rpc", "false", Var.Arg1, Var.Impersonate);
                    break; 
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The disablexp method is used SQL server to disable xp_cmdshell.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void disablexp()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "xp_cmdshell", "0", Var.SqlServer);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "xp_cmdshell", "0", Var.SqlServer, Var.Impersonate);
                    break;
                case "linked":
                    Config.LinkedModuleToggle(Var.Connect, "xp_cmdshell", "0", Var.LinkedSqlServer, Var.SqlServer);
                    break;
                case "chained":
                    Config.LinkedChainModuleToggle(Var.Connect, "xp_cmdshell", "0", Var.LinkedSqlServersChain, Var.SqlServer);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The enableclr method is used against SQL server to enableclr CLR integration.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void enableclr()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "clr enabled", "1", Var.SqlServer);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "clr enabled", "1", Var.SqlServer, Var.Impersonate);
                    break;
                case "linked":
                    Config.LinkedModuleToggle(Var.Connect, "clr enabled", "1", Var.LinkedSqlServer, Var.SqlServer);
                    break;
                case "chained":
                    Config.LinkedChainModuleToggle(Var.Connect, "clr enabled", "1", Var.LinkedSqlServersChain, Var.SqlServer);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The enableole method is used against SQL server to enableole OLE automation.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void enableole()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "Ole Automation Procedures", "1", Var.SqlServer);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "Ole Automation Procedures", "1", Var.SqlServer, Var.Impersonate);
                    break;
                case "linked":
                    Config.LinkedModuleToggle(Var.Connect, "Ole Automation Procedures", "1", Var.LinkedSqlServer, Var.SqlServer);
                    break;
                case "chained":
                    Config.LinkedChainModuleToggle(Var.Connect, "Ole Automation Procedures", "1", Var.LinkedSqlServersChain, Var.SqlServer);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The enablerpc method is used against SQL server to enablerpc 'rpc out' on a specified SQL server.
        /// This module supports execution against SQL server using a standard authentication context,
        /// and impersonation.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void enablerpc()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.DisableOrEnableRpc(Var.Context) == false) return;

            Print.Status($"Enabling RPC on {Var.Arg1}", true);
            Console.WriteLine();
            
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "rpc", "true", Var.Arg1);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "rpc", "true", Var.Arg1, Var.Impersonate);
                    break; 
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The enablexp method is used SQL server to enablexp xp_cmdshell.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void enablexp()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    Config.ModuleToggle(Var.Connect, "xp_cmdshell", "1", Var.SqlServer);
                    break;
                case "impersonation": 
                    Config.ModuleToggle(Var.Connect, "xp_cmdshell", "1", Var.SqlServer, Var.Impersonate);
                    break;
                case "linked":
                    Config.LinkedModuleToggle(Var.Connect, "xp_cmdshell", "1", Var.LinkedSqlServer, Var.SqlServer);
                    break;
                case "chained":
                    Config.LinkedChainModuleToggle(Var.Connect, "xp_cmdshell", "1", Var.LinkedSqlServersChain, Var.SqlServer);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The impersonate method is used against SQL server to
        /// identify if any SQL accounts can be impersonated.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void impersonate()
        {
            // First obtain all SQL users and Windows principals.
            _query = Sql.CustomQuery(Var.Connect, Query.GetSqlUsersAndWindowsPrincipals);
            
            // Extract all user names
            List<string> logins = Print.ExtractColumnValues(_query, "name");

            Dictionary<string, string> impersonationLogins = new Dictionary<string, string>();

            // Next check to see if the user is a sysadmin
            if (Roles.CheckRoleMembership(Var.Connect, "sysadmin"))
            {
                if (logins.Any())
                {
                    foreach (string login in logins)
                    {
                        impersonationLogins.Add(login, "True");
                    }
                }
            }
            else
            {
                if (logins.Any())
                {
                    foreach (string login in logins)
                    {
                        bool canImpersonate = Roles.CheckImpersonation(Var.Connect, login);

                        if (canImpersonate)
                        {
                            impersonationLogins.Add(login, "True");
                        }
                    }
                }
            }

            if (impersonationLogins.Any())
            {
                Console.WriteLine();
                Console.WriteLine(Print.ConvertDictionaryToMarkdownTable(impersonationLogins, "User", "Can Impersonate?"));
            }
            else
            {
                Console.WriteLine();
                Print.Error("No logins can be impersonated.", true);
            }
        }

        /// <summary>
        /// The info method gathers information about the remote SQL server instance.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void info()
        {
            switch(Var.Context) 
            { 
                case "standard" or "impersonation": 
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    Info.StandardOrImpersonation(Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    Info.LinkedOrChain(Var.LinkedSqlServer, Var.LinkedSqlServersChain);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
        }

        /// <summary>
        /// The links method is used to determine if the remote SQL server has a link configured to other SQL servers.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void links()
        {
            switch(Var.Context) 
            { 
                case "standard": 
                    _query = Query.GetLinkedSqlServersVerbose;
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, Query.GetLinkedSqlServersVerbose);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, Query.GetLinkedSqlServersVerbose);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, Query.GetLinkedSqlServersVerbose);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            Console.WriteLine();
            Print.IsOutputEmpty(Sql.CustomQuery(Var.Connect, _query), true);
        }

        /// <summary>
        /// The olecmd method is used against SQL server to execute a user supplied command on the
        /// underlying system.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void olecmd()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.OleCmd(Var.Context) == false) return;
            
            Print.Status($"Executing '{Var.Arg1}'", true);
            Console.WriteLine();

            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    Ole.StandardOrImpersonation(Var.Connect, Var.Arg1, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    Ole.LinkedOrChain(Var.Connect, Var.Arg1, Var.LinkedSqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }

        /// <summary>
        /// The query method is used against SQL server to execute a user supplied SQL query.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void query()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.Query(Var.Context) == false) return;

            Print.Status($"Executing '{Var.Arg1}'", true);

            switch(Var.Context) 
            { 
                case "standard": 
                    _query = Var.Arg1;
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, Var.Arg1);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, Var.Arg1);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, Var.Arg1);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            Console.WriteLine();
            Print.IsOutputEmpty(Sql.CustomQuery(Var.Connect, _query), true);
        }

        /// <summary>
        /// The rows method is used against SQL server to determine the number of rows in a table.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void rows()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.ColumnsOrRows(Var.Context) == false) return;
            
            // Check if RPC is enabled for linked or chained contexts
            if (_checkLinkedRpc(Var.Context) == false) return;
            
            Print.Status($"Displaying number of rows from '{Var.Arg2}' in '{Var.Arg1}'", true);
            
            _query = string.Format(Query.GetRowCount, Var.Arg1, Var.Arg2);
            
            switch(Var.Context) 
            { 
                case "standard": 
                    _query = string.Format(Query.GetRowCount, Var.Arg1, Var.Arg2);
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, _query);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, _query, true);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, string.Format(Query.GetLinkedChainRowCount, Var.Arg1));
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            _query = Sql.CustomQuery(Var.Connect, _query);

            if (string.IsNullOrEmpty(_query))
            {
                Console.WriteLine();
                Print.Error($"No results. If the '{Var.Arg1}' database and '{Var.Arg2}' table exist, " + 
                             "then this is likely a permissions issue.", true);
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(_query);
            }
        }

        /// <summary>
        /// The search method is used against a SQL server to search a table for a specific column name.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void search()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.Search(Var.Context) == false) return;
            
            // Check if RPC is enabled for linked or chained contexts
            if (_checkLinkedRpc(Var.Context) == false) return;
            
            Print.Status($"Searching for columns containing '{Var.Arg2}' in '{Var.Arg1}'", true);
            
            _query = string.Format(Query.SearchColumns, Var.Arg1, Var.Arg2);
            
            switch(Var.Context) 
            { 
                case "standard":
                    _query = string.Format(Query.SearchColumns, Var.Arg1, Var.Arg2); 
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, _query);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, _query, true);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, string.Format(Query.LinkedChainSearchColumns, Var.Arg1));
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            _query = Sql.CustomQuery(Var.Connect, _query);

            if (string.IsNullOrEmpty(_query))
            {
                Console.WriteLine();
                Print.Error($"No results. If the '{Var.Arg1}' database exists, " +
                             "then this is likely a permissions issue.", true);
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(_query);
            }
        }

        /// <summary>
        /// The smb method is used against SQL server to make the SQL server send an
        /// SMB request to an arbitrary host.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void smb()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.Smb(Var.Context) == false) return;
            
            switch(Var.Context) 
            { 
                case "standard": 
                    _query = string.Format(Query.SmbRequest, Var.Arg1);
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, string.Format(Query.SmbRequest, Var.Arg1));
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, string.Format(Query.LinkedSmbRequest, Var.Arg1));
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, string.Format(Query.LinkedSmbRequest, Var.Arg1));
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            Sql.CustomQuery(Var.Connect, _query);
            
            Print.Status("Sent SMB request request", true);
        }

        /// <summary>
        /// The tables method is against SQL server to retrieve the tables from the user supplied database.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void tables()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.Tables(Var.Context) == false) return;
            
            Print.Status($"Tables in '{Var.Arg1}'", true);

            _query = string.Format(Query.GetTables, Var.Arg1);
            
            switch(Var.Context) 
            { 
                case "standard":
                    _query = string.Format(Query.GetTables, Var.Arg1); 
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, _query);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, _query, true);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, _query);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            _query = Sql.CustomQuery(Var.Connect, _query);

            if (string.IsNullOrEmpty(_query))
            {
                Console.WriteLine();
                Print.Error($"No results. If the '{Var.Arg1}' database exists, " +
                             "then this is likely a permissions issue.", true);
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(_query);
            }
        }

        /// <summary>
        /// The users method is used against SQL server to obtain local users in the SQL instance.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void users()
        {
            Print.Status($"Users in the '{Var.Database}' database", true);
            
            switch(Var.Context) 
            { 
                case "standard":
                    _query = Query.GetDatabaseUsers;
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, Query.GetDatabaseUsers);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, Query.GetDatabaseUsers);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, Query.GetDatabaseUsers);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(Var.Connect, _query));
            
            Print.Status("Server principals", true);
            
            switch(Var.Context) 
            { 
                case "standard":
                    _query = Query.GetPrincipals;
                    break;
                case "impersonation": 
                    _query = Format.ImpersonationQuery(Var.Impersonate, Query.GetPrincipals);
                    break;
                case "linked":
                    _query = Format.LinkedQuery(Var.LinkedSqlServer, Query.GetPrincipals);
                    break;
                case "chained":
                    _query = Format.LinkedChainQuery(Var.LinkedSqlServersChain, Query.GetPrincipals);
                    break;
                default:
                    Print.Error($"'{Var.Context}' is not a valid context.", true);
                    break;
            }
            
            Console.WriteLine();
            Console.WriteLine(Sql.CustomQuery(Var.Connect, _query));
        }

        /// <summary>
        /// The whoami method is used against SQL server to determine the current users level of access.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void whoami()
        {
            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    Roles.StandardOrImpersonation(Var.Connect, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    Roles.LinkedOrChain(Var.Connect, Var.LinkedSqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }

        /// <summary>
        /// The xpcmd method is used against SQL server to execute a user supplied command on the
        /// underlying system.
        /// This module supports execution against SQL server using a standard authentication context,
        /// impersonation, linked SQL servers, and chained SQL servers.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void xpcmd()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckSqlArguments.XpCmd(Var.Context) == false) return;
            
            Console.WriteLine($"Executing '{Var.Arg1}'", true);
            Console.WriteLine();
            
            switch (Var.Context)
            {
                case "standard" or "impersonation":
                    // If the context is standard, then Var.Impersonate is null and logic is handled in the module.
                    XpCmdShell.StandardOrImpersonation(Var.Connect, Var.Arg1, Var.Impersonate);
                    break;
                case "linked" or "chained":
                    // If the context is linked, then Var.LinkedSqlServersChain is null and logic is handled in the module.
                    XpCmdShell.LinkedOrChain(Var.Connect, Var.Arg1, Var.LinkedSqlServer, Var.LinkedSqlServersChain);
                    break;
            }
        }
        
        /// <summary>
        /// The _checkLinkedRpc method will determine if RPC is enabled on a linked SQL server
        /// before continuing the execution flow of a module. 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private static bool _checkLinkedRpc(string context)
        {
            switch (context)
            {
                case "linked" or "chained":
                    bool checkLinkedRpc = Config.ModuleStatus(Var.Connect, "rpc", null, Var.LinkedSqlServer);

                    if (checkLinkedRpc)
                    {
                        return true;
                    }
                    else
                    {
                        Print.Error($"You need to enable RPC for {Var.LinkedSqlServer} on {Var.SqlServer} (/m:enablerpc /rhost:{Var.LinkedSqlServer}).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                default:
                    // Return true as we only care about linked or chained contexts.
                    return true;
            }
        }
        
        /// <summary>
        /// The _determineContext method will determine if a user supplied for impersonation
        /// can be impersonated, or if a linked SQL server exists, before progressing onwards
        /// to execute modules in the context of impersonation, linked, or chained contexts.
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
                    case "linked" or "chained":
                        // Obtain a list linked SQL servers
                        string sqlOutput = Sql.CustomQuery(Var.Connect, Query.GetLinkedSqlServers);

                        // Check to see if the linked SQL server exists
                        if (sqlOutput.ToLower().Contains(Var.LinkedSqlServer.ToLower()))
                        {
                            return true;
                        }
                        else
                        {
                            // Go no further
                            Print.Error($"{Var.SqlServer} does not have a linked connection to {Var.LinkedSqlServer}.", true);
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
    /// The CheckSqlArguments class validates arguments which are required for modules.
    /// </summary>
    internal abstract class CheckSqlArguments
    {
        /// <summary>
        /// Required arguments for the adsi module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Adsi(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("adsi") && !string.IsNullOrEmpty(Var.ParsedArguments["adsi"]) &&
                        Var.ParsedArguments.ContainsKey("lport") && !string.IsNullOrEmpty(Var.ParsedArguments["lport"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["adsi"];
                        Var.Arg2 = Var.ParsedArguments["lport"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply an ADSI server name (/adsi:) " +
                                        "and port for the LDAP server to listen on (/lport:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("adsi") && !string.IsNullOrEmpty(Var.ParsedArguments["adsi"]) &&
                        Var.ParsedArguments.ContainsKey("lport") && !string.IsNullOrEmpty(Var.ParsedArguments["lport"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["adsi"];
                        Var.Arg2 = Var.ParsedArguments["lport"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:), " +
                                        "ADSI server name (/adsi:) and port for the LDAP server to " +
                                        "listen on (/lport:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("adsi") && !string.IsNullOrEmpty(Var.ParsedArguments["adsi"]) &&
                        Var.ParsedArguments.ContainsKey("lport") && !string.IsNullOrEmpty(Var.ParsedArguments["lport"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["adsi"];
                        Var.Arg2 = Var.ParsedArguments["lport"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:), " +
                                        "ADSI server name (/adsi:) and port for the LDAP server to " +
                                        "listen on (/lport:).", true);
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
        /// Required arguments for the agentcmd module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool AgentCmd(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]))
                    {
                        Var.Arg2 = Var.ParsedArguments["command"];
                        return true; 
                    }
                    else
                    {
                        Print.Error("Must supply a command (/c:, /command:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false; 
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg2 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:) and a command for this module (/c, /command:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }

                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg2 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) " +
                                        "and a command for this module (/c, /command:).", true);
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
        /// Required arguments for the clr module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Clr(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("dll") && !string.IsNullOrEmpty(Var.ParsedArguments["dll"]) &&
                        Var.ParsedArguments.ContainsKey("function") && !string.IsNullOrEmpty(Var.ParsedArguments["function"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["dll"];
                        Var.Arg2 = Var.ParsedArguments["function"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply location to a DLL (/dll:) and function name (/function:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("dll") && !string.IsNullOrEmpty(Var.ParsedArguments["dll"]) &&
                        Var.ParsedArguments.ContainsKey("function") && !string.IsNullOrEmpty(Var.ParsedArguments["function"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["dll"];
                        Var.Arg2 = Var.ParsedArguments["function"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:), " +
                                        "location to DLL (/dll:) and function name (/function:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("dll") && !string.IsNullOrEmpty(Var.ParsedArguments["dll"]) &&
                        Var.ParsedArguments.ContainsKey("function") && !string.IsNullOrEmpty(Var.ParsedArguments["function"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["dll"];
                        Var.Arg2 = Var.ParsedArguments["function"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:), " +
                                        "location to DLL (/dll:) and function name (/function:).", true);
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
        /// Required arguments for the columns or rows modules.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool ColumnsOrRows(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("table") && !string.IsNullOrEmpty(Var.ParsedArguments["table"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        Var.Arg2 = Var.ParsedArguments["table"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a database (/db:) and table name (/table:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("table") && !string.IsNullOrEmpty(Var.ParsedArguments["table"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        Var.Arg2 = Var.ParsedArguments["table"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:), " +
                                        "a database (/db:) and table name (/table:)", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("table") && !string.IsNullOrEmpty(Var.ParsedArguments["table"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        Var.Arg2 = Var.ParsedArguments["table"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:)," +
                                        "a database (/db:) and table name (/table:)", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "chained":
                    if (Var.ParsedArguments.ContainsKey("table") && !string.IsNullOrEmpty(Var.ParsedArguments["table"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 =Var.ParsedArguments["table"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) and table name (/table:)", true);
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
        /// Required arguments for the disablerpc or enablerpc modules.
        /// Checks performed for standard and impersonation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool DisableOrEnableRpc(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("rhost") && !string.IsNullOrEmpty(Var.ParsedArguments["rhost"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["rhost"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a rhost for this module (/rhost:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("rhost") && !string.IsNullOrEmpty(Var.ParsedArguments["rhost"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["rhost"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:) and a rhost for this module (/rhost:).", true);
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
        /// Required arguments for the olecmd module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool OleCmd(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a command (/c:, /command:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:) and a command for this module (/c, /command:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) " +
                                        "and a command for this module (/c, /command:).", true);
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
        /// Required arguments for the query module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Query(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a command (/c:, /command:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:) and a command for this module (/c, /command:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) " +
                                        "and a command for this module (/c, /command:).", true);
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
        /// Required arguments for the search module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Search(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("keyword") && !string.IsNullOrEmpty(Var.ParsedArguments["keyword"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        Var.Arg2 = Var.ParsedArguments["keyword"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a database (/db:) and keyword (/keyword:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("keyword") && !string.IsNullOrEmpty(Var.ParsedArguments["keyword"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        Var.Arg2 = Var.ParsedArguments["keyword"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:), " +
                                        "a database (/db:) and keyword (/keyword:)", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("keyword") && !string.IsNullOrEmpty(Var.ParsedArguments["keyword"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        Var.Arg2 = Var.ParsedArguments["keyword"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:), " +
                                        "a database (/db:) and keyword (/keyword:)", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "chained":
                    if (Var.ParsedArguments.ContainsKey("keyword") && !string.IsNullOrEmpty(Var.ParsedArguments["keyword"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["keyword"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) and keyword (/keyword:)", true);
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
        /// Required arguments for the smb module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Smb(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("unc") && !string.IsNullOrEmpty(Var.ParsedArguments["unc"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["unc"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a UNC path for this module (/unc:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("unc") && !string.IsNullOrEmpty(Var.ParsedArguments["unc"]) && 
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["unc"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:), " +
                                        "and a UNC path for this module (/unc:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("unc") && !string.IsNullOrEmpty(Var.ParsedArguments["unc"]) && 
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["unc"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) "+
                                        "and a UNC path for this module (/unc:).", true);
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
        /// Required arguments for the tables module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool Tables(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a database (/db:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:) and a database for this module (/db:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("db") && !string.IsNullOrEmpty(Var.ParsedArguments["db"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["db"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) " + 
                                        "and a database for this module (/db:).", true);
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
        /// Required arguments for the xpcmd module.
        /// Checks performed for standard, impersonation, linked, and chained.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static bool XpCmd(string context)
        {
            switch (context)
            {
                case "standard":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a command (/c:, /command:) for this module.", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "impersonation":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("iuser") && !string.IsNullOrEmpty(Var.ParsedArguments["iuser"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a user to impersonate (/i:, /iuser:) and a command for this module (/c, /command:).", true);
                        // Go no further. Gracefully exit.
                        return false;
                    }
                case "linked" or "chained":
                    if (Var.ParsedArguments.ContainsKey("command") && !string.IsNullOrEmpty(Var.ParsedArguments["command"]) &&
                        Var.ParsedArguments.ContainsKey("link") && !string.IsNullOrEmpty(Var.ParsedArguments["link"]))
                    {
                        Var.Arg1 = Var.ParsedArguments["command"];
                        return true;
                    }
                    else
                    {
                        Print.Error("Must supply a linked SQL server (/l:, /link:) " +
                                        "and a command for this module (/c, /command:).", true);
                        // Go no further. Gracefully exit.
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