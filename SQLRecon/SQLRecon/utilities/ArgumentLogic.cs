using System;
using System.Collections.Generic;
using System.Linq;
using SQLRecon.Commands;

namespace SQLRecon.Utilities
{
    internal abstract class ArgumentLogic
    {
        private const string CallingConvention = "/";
        private const char ValueSeparator = ':';
        
        /// <summary>
        /// The ParseArguments method parses user supplied command line arguments
        /// and places the values into a dictionary (key/value pair style).
        /// Arguments are expected to be in '/key:value' format.
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        internal static void ParseArguments(IEnumerable<string> args)
        {
            Dictionary<string, string> parsedArguments = new(StringComparer.InvariantCultureIgnoreCase);

            try
            {
                foreach (string arg in args)
                {
                    // Ensure that the argument starts with "/".
                    if (!arg.StartsWith(CallingConvention))
                    {
                        Print.Error(
                            $"Arguments need to start with the '{CallingConvention}' calling convention. " +
                            "Use '/help' to display the help menu.", true);
                        
                        // Go no further.
                        return;
                    }

                    // Split the argument on a ":" and place into an array.
                    string[] parts = arg.Split(new[] { ValueSeparator }, 2);

                    // Populate the dictionary using the array.
                    if (parts.Length == 2)
                    {
                        parsedArguments[parts[0].ToLower().Substring(1)] = parts[1];
                    }
                    else
                    {
                        parsedArguments[parts[0].ToLower().Substring(1)] = "";
                    }
                }
                
                // Convert any short form arguments to long form, for example '/a:'
                // to '/auth:'. This is for consistency when referencing dictionary keys.
                parsedArguments = _convertArgumentFromShortToLong(parsedArguments);
                
                // Pass the dictionary into _globalVariableAssignment so that dictionary
                // keys can be assigned to a global variable.
                _globalVariableAssignment(parsedArguments);
            }
            catch (ArgumentException)
            {
                Print.Error("Duplicate switches detected. Check your command again.", true);
            }
        }

        /// <summary>
        /// The EvaluateEnumerationModuleArguments method is responsible for determining
        /// what enumeration module to use.
        /// </summary>
        public static void EvaluateEnumerationModuleArguments()
        {
            if (Var.EnumerationModulesAndArgumentCount.ContainsKey(Var.EnumerationModule))
            {
                // Obtain the number of required arguments for each module
                int numberOfRequiredArguments = Var.EnumerationModulesAndArgumentCount[Var.EnumerationModule];
                
                // Print the module and the number of arguments it requires if debug/verbose is true.
                if (Var.Debug)
                {
                    Print.Debug($"Module: {Var.EnumerationModule}");
                    Print.Nested($"Number of required enumeration module arguments: {numberOfRequiredArguments}", true);
                }
                
                // Execute the enumeration module
                EnumerationModules.Execute();
            }
            else
            {
                //Go no further
                Print.Error($"'{Var.EnumerationModule}' is an invalid enumeration module.", true);
            }
        }
        
        /// <summary>
        /// The EvaluateSccmModuleArguments method is responsible for determining
        /// what SCCM module to use.
        /// </summary>
        public static void EvaluateSccmModuleArguments()
        {
            if (Var.SccmModulesAndArgumentCount.ContainsKey(Var.SccmModule))
            {
                // Obtain the number of required arguments for each module
                int[] numberOfRequiredArguments = Var.SccmModulesAndArgumentCount[Var.SccmModule];
                int standardArgumentCount = numberOfRequiredArguments[0];
                int impersonateArgumentCount = numberOfRequiredArguments[1];
                
                // Print the module and the number of arguments it requires if debug/verbose is true.
                if (Var.Debug)
                {
                    Print.Debug($"Module: {Var.SccmModule}");
                    Print.Nested($"Number of required SCCM module arguments: {standardArgumentCount}", true);
                    Print.Nested($"Number of required SCCM module impersonate arguments: {impersonateArgumentCount}", true);
                }
                
                // If the user supplies a user to impersonate, and the required argument count for the
                // corresponding module is -1, then the module does not support impersonation,
                // such as the "impersonate" module.
                if (!string.IsNullOrEmpty(Var.Impersonate) && impersonateArgumentCount == -1)
                {
                    Print.Error($"The '{Var.SccmModule}' module does not support impersonation.", true);
                    // Go no further
                    return;
                }
                
                // If the /iuser flag is present, then the execution mode is impersonation
                Var.Context = !string.IsNullOrEmpty(Var.Impersonate) 
                    ? "impersonation"
                    // If /iuser is not present, then the execution mode is standard
                    : "standard";
                
                // Execute the SCCM module
                SccmModules.Execute();
            }
            else
            {
                //Go no further
                Print.Error($"'{Var.SccmModule}' is an invalid SCCM module.", true);
            }
        }
        
        /// <summary>
        /// The EvaluateSqlModuleArguments method performs logic against the various
        /// commands and associated arguments that are supported by SQLRecon to
        /// ensure that the correct module is selected. All the supported commands
        /// are located in the GlobalVariables.cs file. Commands and the argument count they
        /// support are stored in a key/value pair. Where the key is the command (for example 'query')
        /// and the value is the number of arguments the 'query' command needs, which is 1.
        /// </summary>
        public static void EvaluateSqlModuleArguments()
        {
            if (Var.SqlModulesAndArgumentCount.ContainsKey(Var.Module))
            {
                // Obtain the number of required arguments for each module
                int[] numberOfRequiredArguments = Var.SqlModulesAndArgumentCount[Var.Module];
                int standardArgumentCount = numberOfRequiredArguments[0];
                int impersonateArgumentCount = numberOfRequiredArguments[1];
                int linkedArgumentCount = numberOfRequiredArguments[2];
                
                // Print the module and the number of arguments it requires if debug/verbose is true.
                if (Var.Debug)
                {
                    Print.Debug($"Module: {Var.Module}");
                    Print.Nested($"Number of required standard arguments: {standardArgumentCount}", true);
                    Print.Nested($"Number of required impersonate arguments: {impersonateArgumentCount}", true);
                    Print.Nested($"Number of required linked arguments: {linkedArgumentCount}", true);
                }
                
                // If the user supplies a user to impersonate, and the required argument count for the
                // corresponding module is -1, then the module does not support impersonation,
                // such as the "impersonate" module.
                if (!string.IsNullOrEmpty(Var.Impersonate) && impersonateArgumentCount == -1)
                {
                    Print.Error($"The '{Var.Module}' module does not support impersonation.", true);
                    // Go no further
                    return;
                }

                // If the user supplies a linked SQL server, and the required argument count for the
                // corresponding module is -1, then the module does not support linked execution,
                // such as the "impersonate" module.
                if (!string.IsNullOrEmpty(Var.LinkedSqlServer) && linkedArgumentCount == -1)
                {
                    Print.Error($"The '{Var.Module}' module does not support linked SQL servers.", true);
                    // Go no further
                    return;
                }
                
                // If the /iuser flag is present, then the execution mode is impersonation
                if (!string.IsNullOrEmpty(Var.Impersonate))
                {
                    _prepareSqlModuleForExecution("Impersonation", impersonateArgumentCount);

                }
                else if (!string.IsNullOrEmpty(Var.LinkedSqlServer))
                {
                    // If the /link flag is present, then the execution mode is for linked servers
                    _prepareSqlModuleForExecution("Linked", linkedArgumentCount);
                }
                else
                {
                    // If /iuser, or /link is not present, then the execution mode is standard
                    _prepareSqlModuleForExecution("Standard", standardArgumentCount);
                }
            }
            else
            {
                // Go no further
                Print.Error($"'{Var.Module}' is an invalid SQL module.", true);
            }
        }

        /// <summary>
        /// The _convertArgumentFromShortToLong method will convert any arguments supplied on the 
        /// command line from short form to long form as long form is used throughout the program.
        /// For example, if a user supplied '/a:' it will be converted to '/auth:'.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static Dictionary<string, string> _convertArgumentFromShortToLong(Dictionary<string, string> argumentDictionary)
        {
            foreach (KeyValuePair<string, string> flag in Var.CoreCommands)
            {
                if (argumentDictionary.ContainsKey(flag.Key))
                {
                    string originalValue = argumentDictionary[flag.Key];
                    argumentDictionary.Remove(flag.Key);
                    argumentDictionary.Add(flag.Value, originalValue);
                }
            }
            return argumentDictionary;
        }
        
        /// <summary>
        /// The _globalVariableAssignment method assigns dictionary values to corresponding global variables.
        /// All parsed arguments are stored in the ParsedArguments global variable.
        /// This method does some error handling for multiple hosts that are supplied to the /hosts
        /// and/or /link arguments. Additional error handling is also performed to create conditions where
        /// restrictions are necessary. For example, an impersonation user can not be used against linked system (yet).
        /// </summary>
        /// <param name="parsedArguments"></param>
        private static void _globalVariableAssignment(Dictionary<string, string> parsedArguments)
        {
            // Assign user supplied input into some global variables. Lowercase the module name to standardize 
            // references throughout the program.
            Var.AuthenticationType = parsedArguments.ContainsKey("auth") ? parsedArguments["auth"].ToLower() : null;
            Var.Domain = parsedArguments.ContainsKey("domain") ? parsedArguments["domain"] : null;
            Var.EnumerationModule = parsedArguments.ContainsKey("enum") ? parsedArguments["enum"] : null;
            Var.Impersonate = parsedArguments.ContainsKey("iuser") ? parsedArguments["iuser"] : null;
            Var.LinkedSqlServerChain = parsedArguments.ContainsKey("chain");
            Var.Module = parsedArguments.ContainsKey("module") ? parsedArguments["module"].ToLower() : null;
            Var.Password = parsedArguments.ContainsKey("password") ? parsedArguments["password"] : null;
            Var.Username = parsedArguments.ContainsKey("username") ? parsedArguments["username"] : null;
            Var.SccmModule = parsedArguments.ContainsKey("sccm") ? parsedArguments["sccm"].ToLower() : null;

            // Print the help menu if the "/help" flag is supplied.
            if (parsedArguments.ContainsKey("help"))
            {
                Help _ = new();
                // Go no further.
                return;
            }
            
            // Set the database to the value supplied in the "/database" flag and assign into Var.Database.
            // Otherwise, the default value is master.
            if (parsedArguments.ContainsKey("database"))
            {
                Var.Database = parsedArguments["database"];
            }
            
            // Set the port to the value supplied in the "/port" flag and assign into Var.Port.
            // Otherwise, the default value is 1433.
            if (parsedArguments.ContainsKey("port"))
            {
                Var.Port = parsedArguments["port"];
            }
            
            // Set the timeout to the value supplied in the "/timeout" flag and assign into Var.Timeout.
            // Otherwise, the default value is 4.
            if (parsedArguments.ContainsKey("timeout"))
            {
                Var.Timeout = parsedArguments["timeout"];
            }
            
            // Enable debug if the "/debug" flag is supplied and assign into Var.Debug.
            if (parsedArguments.ContainsKey("debug"))
            {
                Var.Debug = true;
                Print.Status("Debug mode enabled. No SQL queries will be executed.", true);
            }
            
            // Enable verbosity if the "/verbose" or "/v" flag is supplied and assign into Var.Verbose.
            if (parsedArguments.ContainsKey("verbose"))
            {
                Var.Verbose = true; 
            }
            
            // Check for single or multiple hosts in "/host" or "/h" and assign into Var.sqlServers
            if (parsedArguments.ContainsKey("host"))
            {
                // Var.SqlServers is an array which contains the single host, or comma-seperated hosts
                // supplied into the "/host" variable 
                Var.SqlServers = parsedArguments["host"].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            
                // Set the first host in the Var.SqlServers array to the initial connection host.
                Var.SqlServer = Var.SqlServers[0];
            } 
            
            // Check single or multiple hosts in "/link" or "/l" and assign into Var.linkedSqlServers
            if (parsedArguments.ContainsKey("link"))
            {
                // Var.LinkedServers is an array which contains the single linked host, or comma-seperated linked hosts
                // supplied into the "/link" variable 
                Var.LinkedSqlServers = parsedArguments["link"].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                
                // Set the first host in the Var.LinkedSqlServers array to the initial linked connection host.
                Var.LinkedSqlServer = Var.LinkedSqlServers[0]; 
            }
            
            // Create a limitation where users can not specify both the /link and /iuser flag
            if (parsedArguments.ContainsKey("link") && parsedArguments.ContainsKey("iuser"))
            {
                Print.Error("The linked SQL server flag (/link, /l) and a user to impersonate " +
                             "(/iuser, /i) was supplied. SQLRecon only supports one or the other.", true);
                // Go no further.
                return;
            }
            
            // Create a limitation where users can not specify both the /chain and /iuser flag
            if (parsedArguments.ContainsKey("chain") && parsedArguments.ContainsKey("iuser"))
            {
                Print.Error("The linked SQL server chain flag (/chain) and a user to impersonate " +
                             "(/iuser, /i) was supplied. SQLRecon only supports one or the other.", true);
                // Go no further.
                return;
            }

            /*
             * Create a limitation where if multiple SQL servers are supplied in "/hosts", then
             * executing modules against linked servers supplied in "/link" is not possible. In addition,
             * if multiple linked servers are supplied in "/link", then only one host can be present in the
             * "/host" variable.
             */
            if (parsedArguments.ContainsKey("host") && parsedArguments.ContainsKey("link"))
            {
                if ((Var.SqlServers.Length > 1 && Var.LinkedSqlServers.Length > 0))
                {
                    Print.Error("SQLRecon supports the execution of modules against multiple SQL servers " +
                                 "supplied in the /host or /h argument. However, it is not possible to execute linked " +
                                 "commands against multiple SQL Servers as the linked servers supplied in /link or /l may " +
                                 "not exist on all remote SQL servers.", true);
                    // Go no further.
                    return;
                }
            }

            /*
             * Create a limitation where if multiple SQL servers are supplied in "/hosts", then
             * executing modules against linked SQL server chain supplied in "/link" is not possible, if the "/chain" flag is present.
             * In addition, if multiple linked SQL servers are supplied in "/link", then only one host can be present in the
             * "/host" variable.
             */
            if (parsedArguments.ContainsKey("host") && parsedArguments.ContainsKey("link") && parsedArguments.ContainsKey("chain"))
            {
                if ((Var.SqlServers.Length > 1 && Var.LinkedSqlServers.Length > 0) && Var.LinkedSqlServerChain)
                {
                    Print.Error("SQLRecon supports the execution of modules against linked SQL servers, and SQL servers linked " + 
                                 "off a linked SQL server. However, it is not possible to execute commands against multiple SQL servers" +
                                 "supplied in the /host or /h argument, as the linked chain supplied in /link or /l may not" +
                                 "exist on all remote SQL servers.", true);
                    // Go no further.
                    return;
                }
            }
            
            // Assign parsedArguments into Var.ParsedArguments global variable.
            Var.ParsedArguments = _convertArgumentFromShortToLong(parsedArguments);
            
            // Print the CLI arguments if the /debug or /verbose flags are supplied
            if (Var.Debug || Var.Verbose)
            {
                Print.Debug("CLI Arguments:");
                foreach(KeyValuePair<string, string> entry in Var.ParsedArguments) 
                {
                    Print.Nested($"/{entry.Key}:{entry.Value}", true);
                }
            }
        }
        
        /// <summary>
        /// The _prepareModuleForExecution method directs the module execution to the correct location,
        /// whether that is standard (against a single or multiple SQL servers), impersonation,
        /// or linked. In addition, the execution of modules against multiple SQL servers, or linked
        /// SQL servers is handled in this method.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="argCount"></param>
        private static void _prepareSqlModuleForExecution(string context, int argCount = 0)
        {
            if (Var.Debug)
            {
                Print.Debug($"Context Selected: {context}");
                Print.Nested($"Module: {Var.Module}", true);
                Print.Nested($"Number of required arguments: {argCount}", true);    
            }
            
            // This sets the context for all SQL module logic.
            Var.Context = context.ToLower();

            if (Var.Context == "standard")
            {
                // Check to see if multiple SQL servers have been supplied
                if (Var.SqlServers.Length > 1)
                {
                    for (int i = 0; i < Var.SqlServers.Length; i++)
                    {
                        // Set the Var.SqlServer global variable to the current SQL server in the array 
                        Var.SqlServer = Var.SqlServers[i];
                        
                        // Create a new SQL connection object
                        Var.Connect = SetAuthenticationType.CreateSqlConnectionObject();
                        
                       if (Var.Connect == null)
                       {
                           Console.WriteLine();
                           Print.Error($"Connection to '{Var.Database}' on {Var.SqlServer} failed. Skipping this host.", true);
                       }
                       else
                       {
                           Console.WriteLine();
                           Print.Status($"({i+1}/{Var.SqlServers.Length}) Executing the '{Var.Module}' module on {Var.SqlServers[i]}", true);
                           Console.WriteLine();
                           
                           // Execute the module against the current SQL server
                           SqlModules.Execute();
                       }
                    }
                }
                else
                {
                    Print.Status($"Executing the '{Var.Module}' module on {Var.SqlServer}", true);
                    Console.WriteLine();
                    
                    // Execute the module against a single SQL server
                    SqlModules.Execute();
                }
            }
            else if (Var.Context == "impersonation")
            {
                // Check to see if multiple SQL servers have been supplied
                if (Var.SqlServers.Length > 1)
                {
                    for (int i = 0; i < Var.SqlServers.Length; i++)
                    {
                        // Set the Var.SqlServer global variable to the current SQL server in the array 
                        Var.SqlServer = Var.SqlServers[i];
                        
                        // Create a new SQL connection object
                        Var.Connect = SetAuthenticationType.CreateSqlConnectionObject();
                        
                        if (Var.Connect == null)
                        {
                            Console.WriteLine();
                            Print.Error($"Connection to '{Var.Database}' on {Var.SqlServer} failed. Skipping this host.", true);
                        }
                        else
                        {
                            Console.WriteLine();
                            Print.Status($"({i+1}/{Var.SqlServers.Length}) Executing the '{Var.Module}' module on {Var.SqlServers[i]} as '{Var.Impersonate}'", true);
                            Console.WriteLine();
                           
                            // Execute the module against the current SQL server
                            SqlModules.Execute();
                        }
                    }
                }
                else
                {
                    Print.Status($"Executing the '{Var.Module}' module on {Var.SqlServer} as '{Var.Impersonate}'", true);
                    Console.WriteLine();
                    
                    // Execute the module against a single SQL server
                    SqlModules.Execute();
                }
                
                
            }
            else if (Var.Context == "linked")
            {
                // Check to see if multiple linked SQL servers have been supplied
                // Execute modules against each linked server that is present on a single 
                // SQL server.
                if (Var.LinkedSqlServers.Length > 1 && Var.LinkedSqlServerChain == false)
                {
                    for (int i = 0; i < Var.LinkedSqlServers.Length; i++)
                    {
                        // Set the Var.LinkedSqlServer global variable to the current SQL server in the array 
                        Var.LinkedSqlServer = Var.LinkedSqlServers[i];
                        
                        Console.WriteLine();
                        Print.Status($"({i+1}/{Var.LinkedSqlServers.Length}) Executing the '{Var.Module}' module on {Var.LinkedSqlServers[i]} via {Var.SqlServer}", true);
                        Console.WriteLine();
                        
                        // Execute the module against the current SQL server
                        SqlModules.Execute();
                    }
                }
                // Check to see if a chain of SQL servers have been supplied.
                else if (Var.LinkedSqlServers.Length > 1 && Var.LinkedSqlServerChain)
                {
                    // If Var.LinkedSqlServerChain is true, set Var.Context to chained. 
                    Var.Context = "chained";
                    
                    // Format the Var.LinkedSqlServers array so that it meets the Format.LinkedChainQuery
                    // expectation of {"0", "linked sql server", "linked sql server", "linked sql server" ... }
                    Var.LinkedSqlServersChain = new[] { "0" }.Concat(Var.LinkedSqlServers).ToArray();
                    
                    Print.Status($"Setting the chain path to {Var.SqlServer + " -> " +  string.Join(" -> ", Var.LinkedSqlServers)}", true);
                    Console.WriteLine();
                    Print.Status($"Executing the '{Var.Module}' module on {Var.LinkedSqlServersChain.Last()}", true);
                    Console.WriteLine();
                    
                    // After copying Var.LinkedSqlServers to Var.LinkedSqlServersChain, assign it to null.
                    // this is important for logic reasons.
                    Var.LinkedSqlServers = null;
                    
                    // Execute the module against a linked chain SQL server
                    SqlModules.Execute();
                }
                else
                {
                    Print.Status($"Executing the '{Var.Module}' on {Var.LinkedSqlServer} via {Var.SqlServer}", true);
                    Console.WriteLine();
                    
                    // Execute the module against a linked SQL server
                    SqlModules.Execute();
                }
            }
            else
            {
                Print.Error("Invalid mode. SQLRecon supports standard, impersonation, and linked.",true);
            }
        }
    }
}
