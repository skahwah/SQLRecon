using System;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon
{
    internal abstract class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Help _ = new();
            }
            else
            {
                try
                {
                    // Take arguments supplied via the command line, parse them, and assign to 
                    // global variables located in GlobalVariables.cs.
                    ArgumentLogic.ParseArguments(args);
                    
                    // Enumeration modules do not need SQL authentication to be set.
                    if (Var.ParsedArguments.ContainsKey("enum"))
                    {
                        ArgumentLogic.EvaluateEnumerationModuleArguments();
                    }
                    // SQL modules need SQL authentication to be set.
                    else if (Var.ParsedArguments.ContainsKey("module"))
                    {
                        // Set the authentication type, if conditions have passed, evaluate the arguments.
                        if (SetAuthenticationType.EvaluateAuthenticationType(Var.AuthenticationType))
                        {
                            ArgumentLogic.EvaluateSqlModuleArguments();
                        }
                    }
                    // SCCM modules need SQL authentication to be set.
                    else if (Var.ParsedArguments.ContainsKey("sccm"))
                    {
                        // Set the authentication type, if conditions have passed, evaluate the arguments.
                        if (SetAuthenticationType.EvaluateAuthenticationType(Var.AuthenticationType))
                        {
                            ArgumentLogic.EvaluateSccmModuleArguments();
                        }
                    }
                    else
                    {
                        // Go no further.
                        Print.Error("Use the '/help' flag to display the help menu.", true);
                    }
                }
                catch (Exception)
                {
                    // Go no further.
                }
            }
        }
    }
}