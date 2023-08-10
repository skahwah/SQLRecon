using System;
using System.Collections.Generic;
using SQLRecon.Utilities;

namespace SQLRecon
{
    class Program
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
                    // Take arguments supplied via the command line and parse them into a dictionary.
                    Dictionary<string, string> parsedArgs = ArgumentLogic.ParseArguments(args);

                    /* The ParseArguments method will return a key and value pairing of "Error"
                     * if any errors have been encountered during parsing. This is used as an
                     * indicator to gracefully exit the program.
                     */
                    if (parsedArgs.ContainsKey("Error") && parsedArgs.ContainsValue("Error"))
                        // Go no further
                        return;

                    if (parsedArgs.ContainsKey("auth"))
                    {
                        // Set the authentication type, if conditions have passed, evaluate the arguments.
                        if (SetAuthenticationType.EvaluateAuthenticationType(parsedArgs))
                            ArgumentLogic.EvaluateTheArguments(parsedArgs);
                    }
                    else if (parsedArgs.ContainsKey("enum"))
                    {
                        SetEnumerationType.EvaluateEnumerationType(parsedArgs);
                    }
                    else
                    {
                        Console.WriteLine("Use the '/help' flag to display the help menu.");
                        // Go no further
                        return;
                    }
                }
                catch (Exception)
                {
                    // Go no further.
                    return;
                }
            }
        } 


    }
}
