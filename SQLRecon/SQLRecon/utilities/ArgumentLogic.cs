using System;
using System.Collections.Generic;
using SQLRecon.Commands;

namespace SQLRecon.Utilities
{
    internal class ArgumentLogic
    {
        private static readonly GlobalVariables _gV = new();
        private static readonly PrintUtils _print = new();

        private const string _CALLING_CONVENTION = "/";
        private const char _VALUE_SEPARATOR = ':';
        private static readonly Dictionary<string, string> _coreCommands = _gV.CoreCommands;
        private static readonly Dictionary<string, int> _standardArgumentsAndOptionCount = _gV.StandardArgumentsAndOptionCount;
        private static readonly Dictionary<string, int> _impersonationArgumentsAndOptionCount = _gV.ImpersonationArgumentsAndOptionCount;
        private static readonly Dictionary<string, int> _linkedArgumentsAndOptionCount = _gV.LinkedArgumentsAndOptionCount;
        private static readonly Dictionary<string, int> _sccmArgumentsAndOptionCount = _gV.SccmArgumentsAndOptionCount;

        /// <summary>
        /// The ParseArguments method parses user supplied command line arguments
        /// and places the values into a dictionary (key/value pair style). 
        /// Arguments are expected to be in '/key:value' format.
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        internal static Dictionary<string, string> ParseArguments(IEnumerable<string> args)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

            try
            {
                foreach (string arg in args)
                {
                    // Ensure that the argument starts with "/".
                    if (!arg.StartsWith(_CALLING_CONVENTION))
                    {
                        _print.Error(string.Format("Arguments need to start with the '{0}' calling convention. " +
                            "Use '/help' to display the help menu.", _CALLING_CONVENTION.ToString()), true);
                        result.Add("Error", "Error");
                        return result;
                    }

                    // Split the argument on a ":" and place into an array.
                    string[] parts = arg.Split(new char[] { _VALUE_SEPARATOR }, 2);

                    // Populate the dictionary using the array,
                    if (parts.Length == 2)
                    {
                        result[parts[0].ToLower().Substring(1)] = parts[1];
                    }
                    else
                    {
                        result[parts[0].ToLower().Substring(1)] = "";
                    }
                }

                // Print the Help menu if the "/help" flag is supplied.
                if (result.ContainsKey("help"))
                {
                    Help _ = new();
                    result.Add("Error", "Error");
                    return result;
                }

                // Convert any short form arguments to long form
                // For example '/a:' to  '/auth:'.
                return _convertArgumentFromShortToLong(result);
            }
            catch (ArgumentException)
            {
                _print.Error("Duplicate switches detected. Check your command again.", true);
                result.Add("Error", "Error");
                return result;
            }
        }

        /// <summary>
        /// The EvaluateTheArguments method performs logic against the various
        /// commands and associated arguments that are supported by SQLRecon to
        /// ensure that the correct module is selected. All of the supported commands
        /// are located in the GlobalVariables.cs file. Commands and the argument count they
        /// support are stored in a key/value pair. Where the key is the command (for example 'query')
        /// and the value is the number of arguments the 'query' command needs, which is 1.
        /// </summary>
        /// <param name="argDict">The argDict dictionary contains the modules to be used by SQLRecon.</param>
        public static void EvaluateTheArguments(Dictionary<string, string> argDict)
        {
            if (_standardArgumentsAndOptionCount.TryGetValue(argDict["module"].ToLower(), out int standardArgumentCount))
            {
                _checkStandard(argDict, standardArgumentCount);
            }
            else if (_impersonationArgumentsAndOptionCount.TryGetValue(argDict["module"].ToLower(), out int impersonationArgumentCount))
            {
                _checkImpersonation(argDict, impersonationArgumentCount);
            }
            else if (_linkedArgumentsAndOptionCount.TryGetValue(argDict["module"].ToLower(), out int linkedArgumentCount))
            {
                _checkLinked(argDict, linkedArgumentCount);
            }
            else if (_sccmArgumentsAndOptionCount.TryGetValue(argDict["module"].ToLower(), out int sccmArgumentCount))
            {
                _checkSccm(argDict, sccmArgumentCount);
            }
            else
            {
                _print.Error("Invalid module.", true);
                // Go no further.
                return;
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
            foreach (var flag in _coreCommands)
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
        /// The _checkStandard method is reponsible for validating that the supplied
        /// command is structured correctly and has the appropriate arguments, if
        /// necessary for a specific module. This function performs error handling for
        /// all standard SQL moduels if the structure of a command is valid, 
        /// global variables are set and a call is made to the ModuleHandler class.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <param name="argumentCount"></param>
        private static void _checkStandard(Dictionary<string, string> argumentDictionary, int argumentCount = 0)
        {
            if (argumentCount == 0)
            {
                if (argumentDictionary.ContainsKey("module"))
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/db:' flag.
            else if (argumentCount == 1 && argumentDictionary["module"].ToLower().Equals("tables"))
            {
                if (!argumentDictionary.ContainsKey("db"))
                {
                    _print.Error("Must supply a database for this module (/db:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/keyword:' flag.
            else if (argumentCount == 1 && argumentDictionary["module"].ToLower().Equals("search"))
            {
                if (!argumentDictionary.ContainsKey("keyword"))
                {
                    _print.Error("Must supply a keyword for this module (/keyword:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["keyword"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/rhost:' flag.
            else if (argumentCount == 1 && argumentDictionary["module"].ToLower().Equals("disablerpc") ||
                argumentDictionary["module"].ToLower().Equals("enablerpc") ||
                argumentDictionary["module"].ToLower().Equals("smb"))
            {
                if (!argumentDictionary.ContainsKey("rhost"))
                {
                    _print.Error("Must supply a rhost for this module (/rhost:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["rhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/c:, /command:' flag.
            else if (argumentCount == 1 && argumentDictionary["module"].ToLower().Equals("agentcmd") ||
                argumentDictionary["module"].ToLower().Equals("olecmd") ||
                argumentDictionary["module"].ToLower().Equals("xpcmd") ||
                argumentDictionary["module"].ToLower().Equals("query"))
            {
                if (!argumentDictionary.ContainsKey("command"))
                {
                    _print.Error("Must supply a command for this module (/c:, /command:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["command"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/db:' and '/table:' flags.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("columns") ||
                argumentDictionary["module"].ToLower().Equals("rows"))
            {
                if (!argumentDictionary.ContainsKey("db") || !argumentDictionary.ContainsKey("table"))
                {
                    _print.Error("Must supply a database (/db:) and table name (/table:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    _gV.Arg2 = argumentDictionary["table"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the clr module.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("clr"))
            {
                if (!argumentDictionary.ContainsKey("dll") || !argumentDictionary.ContainsKey("function"))
                {
                    _print.Error("Must supply location to a DLL (/dll:) and function name (/function:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["dll"];
                    _gV.Arg2 = argumentDictionary["function"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the adsi module.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("adsi"))
            {
                if (!argumentDictionary.ContainsKey("rhost") || !argumentDictionary.ContainsKey("lport"))
                {
                    _print.Error("Must supply an ADSI server name (/rhost:) and port for the LDAP server to listen on (/lport:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["rhost"];
                    _gV.Arg2 = argumentDictionary["lport"];
                    ModuleHandler.ExecuteModule();
                }
            }
            else
            {
                _print.Error("Invalid module.", true);
                // Go no further.
                return;
            }
        }

        /// <summary>
        /// The _checkImpersonation method is reponsible for validating that the supplied
        /// command is structured correctly and has the appropriate arguments, if
        /// necessary for a specific module. This function performs error handling for
        /// all impersonation SQL modules if the structure of a command is valid, 
        /// global variables are set and a call is made to the ModuleHandler class.       
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <param name="argumentCount"></param>
        private static void _checkImpersonation(Dictionary<string, string> argumentDictionary, int argumentCount = 1)
        {
            // First check if the "/i:, /iuser:" flag has been supplied.
            if (argumentCount == 1)
            {
                if (!argumentDictionary.ContainsKey("iuser"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:).", true);
                    // Go no further.
                    return;
                }
                else
                {

                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Impersonate = argumentDictionary["iuser"];
                    _checkOptionalArgument(argumentDictionary);
                    ModuleHandler.ExecuteModule();

                }
            }
            // This is a custom error message and flag assignment for modules which use the '/db:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("itables"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("db"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:) and a database for this module (/db:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();

                }
            }
            // This is a custom error message and flag assignment for modules which use the '/keyword:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("isearch"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("keyword"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:) and a keyword for this module (/keyword:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["keyword"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();

                }
            }
            // This is a custom error message and flag assignment for modules which use the '/rhost:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("idisablerpc") ||
                argumentDictionary["module"].ToLower().Equals("ienablerpc"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("rhost"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:) and a rhost for this module (/rhost:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["rhost"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();

                }
            }
            // This is a custom error message and flag assignment for modules which use the '/command:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("iagentcmd") ||
                argumentDictionary["module"].ToLower().Equals("iolecmd") ||
                argumentDictionary["module"].ToLower().Equals("ixpcmd") ||
                argumentDictionary["module"].ToLower().Equals("iquery"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("command"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:) and a command for this module (/c:, /command:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["command"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();

                }
            }
            // This is a custom error message and flag assignment for modules which use the '/db:' and '/table:' flags.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("icolumns") ||
                argumentDictionary["module"].ToLower().Equals("irows"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("db") || !argumentDictionary.ContainsKey("table"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:), a database (/db:) and table name (/table:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    _gV.Arg2 = argumentDictionary["table"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();

                }
            }
            // This is a custom error message and flag assignment for the iclr module.
            else if (argumentCount == 3 && argumentDictionary["module"].ToLower().Equals("iclr"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("dll") || !argumentDictionary.ContainsKey("function"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:), location to DLL (/dll:) and function name (/function:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["dll"];
                    _gV.Arg2 = argumentDictionary["function"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the iadsi module.
            else if (argumentCount == 3 && argumentDictionary["module"].ToLower().Equals("iadsi"))
            {
                if (!argumentDictionary.ContainsKey("iuser") || !argumentDictionary.ContainsKey("rhost") || !argumentDictionary.ContainsKey("lport"))
                {
                    _print.Error("Must supply a user to impersonate (/i:, /iuser:), ADSI server name (/rhost:) and port for the LDAP server to listen on (/lport:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["rhost"];
                    _gV.Arg2 = argumentDictionary["lport"];
                    _gV.Impersonate = argumentDictionary["iuser"];
                    ModuleHandler.ExecuteModule();
                }
            }
            else
            {
                _print.Error("Invalid module.", true);
                // Go no further.
                return;
            }
        }

        /// <summary>
        /// The _checkLinked method is reponsible for validating that the supplied
        /// command is structured correctly and has the appropriate arguments, if
        /// necessary for a specific module. This function performs error handling for
        /// all linked SQL server modules if the structure of a command is valid, 
        /// global variables are set and a call is made to the ModuleHandler class.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <param name="argumentCount"></param>
        private static void _checkLinked(Dictionary<string, string> argumentDictionary, int argumentCount = 1)
        {
            // First check if the "/l:, /lhost:" flag has been supplied.
            if (argumentCount == 1)
            {
                if (!argumentDictionary.ContainsKey("lhost"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    _checkOptionalArgument(argumentDictionary);
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/rhost:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("lsmb"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("rhost"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:) and a rhost for this module (/rhost:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["rhost"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/db:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("ltables"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("db"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:) and a database for this module (/db:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for modules which use the '/c:, /command:' flag.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("lquery") ||
                argumentDictionary["module"].ToLower().Equals("lxpcmd") ||
                argumentDictionary["module"].ToLower().Equals("lolecmd") ||
                argumentDictionary["module"].ToLower().Equals("lagentcmd"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("command"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:) and a command for this module (/command:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["command"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for  modules which use the '/db:' and '/table:' flags.
            else if (argumentCount == 3 && argumentDictionary["module"].ToLower().Equals("lcolumns") ||
                 argumentDictionary["module"].ToLower().Equals("lrows"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("db") || !argumentDictionary.ContainsKey("table"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:), a database (/db:) and table name (/table:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    _gV.Arg2 = argumentDictionary["table"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the lsearch module.
            else if (argumentCount == 3 && argumentDictionary["module"].ToLower().Equals("lsearch"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("db") || !argumentDictionary.ContainsKey("keyword"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:), a database (/db:) and keyword (/keyword:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["db"];
                    _gV.Arg2 = argumentDictionary["keyword"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the lclr module.
            else if (argumentCount == 3 && argumentDictionary["module"].ToLower().Equals("lclr"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("dll") || !argumentDictionary.ContainsKey("function"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:), location to DLL (/dll:) and function name (/function:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["dll"];
                    _gV.Arg2 = argumentDictionary["function"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the ladsi module.
            else if (argumentCount == 3 && argumentDictionary["module"].ToLower().Equals("ladsi"))
            {
                if (!argumentDictionary.ContainsKey("lhost") || !argumentDictionary.ContainsKey("rhost") || !argumentDictionary.ContainsKey("lport"))
                {
                    _print.Error("Must supply a linked SQL server (/l:, /lhost:), ADSI server name (/rhost:) and port for the LDAP server to listen on (/lport:).", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["rhost"];
                    _gV.Arg2 = argumentDictionary["lport"];
                    _gV.LinkedSqlServer = argumentDictionary["lhost"];
                    ModuleHandler.ExecuteModule();
                }
            }
            else
            {
                _print.Error("Invalid module.", true);
                // Go no further.
                return;
            }
        }

        /// <summary>
        /// The _checkStandard method is reponsible for validating that the supplied
        /// command is structured correctly and has the appropriate arguments, if
        /// necessary for a specific module. This function performs error handling for
        /// all standard SQL moduels if the structure of a command is valid, 
        /// global variables are set and a call is made to the ModuleHandler class.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <param name="argumentCount"></param>
        private static void _checkSccm(Dictionary<string, string> argumentDictionary, int argumentCount = 0)
        {
            if (argumentCount == 0)
            {
                if (argumentDictionary.ContainsKey("module"))
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _checkOptionalArgument(argumentDictionary);
                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the saddadmin module.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("saddadmin"))
            {
                if (!argumentDictionary.ContainsKey("user") || !argumentDictionary.ContainsKey("sid"))
                {
                    _print.Error("Use '/user:current /sid:current' if you want to set 'Full Administrator' privileges " +
                        "on the current user account. Or use '/user:DOMAIN\\USERNAME /sid:SID' to set 'Full Administrator' " +
                        "privileges on a target account.", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["user"];

                    if (argumentDictionary["sid"].ToLower().Equals("current"))
                    {
                        _gV.Arg2 = "";
                    }
                    else
                    {
                        _gV.Arg2 = argumentDictionary["sid"];
                    }

                    ModuleHandler.ExecuteModule();
                }
            }
            // This is a custom error message and flag assignment for the sremoveadmin module.
            else if (argumentCount == 2 && argumentDictionary["module"].ToLower().Equals("sremoveadmin"))
            {
                if (!argumentDictionary.ContainsKey("user") || !argumentDictionary.ContainsKey("remove"))
                {
                    _print.Error("Must include AdminID (/user:) and permissions string (/remove:) to remove 'Full Administrator' privileges from the target account.", true);
                    // Go no further.
                    return;
                }
                else
                {
                    _gV.Module = argumentDictionary["module"].ToLower();
                    _gV.Arg1 = argumentDictionary["user"];
                    _gV.Arg2 = argumentDictionary["remove"];
                    ModuleHandler.ExecuteModule();
                }
            }
            else
            {
                _print.Error("Invalid module.", true);
                // Go no further.
                return;
            }
        }

        /// <summary>
        /// The _checkOptionalArgument is intended for universal use for any module
        /// that passes in the  '/option:' flag. Modules can and may include optional arguments. 
        /// If a user passes an argument into '/option:' and it enters a module that is not looking
        /// for the '/option:' key, operations will be unaffected. Arguments passed into '/option:'
        /// will always be assigned to the Arg0 global variable, and later in _arg0 in
        /// ModuleHandler.
        /// </summary>
        private static void _checkOptionalArgument(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary.ContainsKey("option"))
            {
                if (argumentDictionary["option"] != null)
                {
                    _gV.Arg0 = argumentDictionary["option"];
                }
                else
                {
                    _gV.Arg0 = "";
                }
            }
        }
    }
}
