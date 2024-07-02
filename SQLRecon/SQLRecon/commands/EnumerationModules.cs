using System;
using System.Reflection;
using SQLRecon.Modules;
using SQLRecon.Utilities;

namespace SQLRecon.Commands
{
    internal abstract class EnumerationModules
    {
        /// <summary>
        /// The Execute method will match the user supplied module in the
        /// Var.EnumerationModule variable against a method name and use reflection to execute
        /// the method in the local class.
        /// </summary>
        internal static void Execute()
        {
            // Reference: https://t.ly/rTjmp
            // Set the type name to this local class.
            Type type = Type.GetType(MethodBase.GetCurrentMethod().DeclaringType.ToString());

            if (type != null)
            {
                // Match the method name to the enumeration module that has been supplied as an argument.
                MethodInfo method = type.GetMethod(Var.EnumerationModule);

                if (method != null)
                {
                    // Call the method.
                    method.Invoke(null, null);
                }
                else
                {
                    // Go no further.
                    Print.Error($"'{Var.EnumerationModule}' is an invalid enumeration module.", true);
                }
            }
        }

        /// <summary>
        /// The info method will send a UDP request to port 1434 on the remote SQL server
        /// along with the magic byte value of 0x02 to receive information about the
        /// SQL instance.
        /// An optional timeout argument is accepted.
        /// An optional port argument is accepted.
        /// Execution against multiple hosts using comma seperated values is supported.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void info()
        {
            // Check if the required arguments are in place, otherwise, gracefully exit.
            if (CheckEnumArguments.Info() == false) return;
            
            if (Var.SqlServers.Length > 1)
            {
                for (int i = 0; i < Var.SqlServers.Length; i++)
                {
                    // Set the Var.SqlServer global variable to the current SQL server in the array 
                    Var.SqlServer = Var.SqlServers[i];

                    Console.WriteLine();
                    Print.Status($"({i + 1}/{Var.SqlServers.Length}) " +
                                     $"Executing the 'info' enumeration module on {Var.SqlServers[i]}", true);

                    Console.WriteLine();
                    Console.WriteLine(Info.GetInfoViaUdpRequest(Var.SqlServer, Int32.Parse(Var.Port), Int32.Parse(Var.Timeout)));
                }
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(Info.GetInfoViaUdpRequest(Var.SqlServer, Int32.Parse(Var.Port), Int32.Parse(Var.Timeout)));
            }
        }

        /// <summary>
        /// The sqlspns method will enumerate if any hosts in the domain have SQL SPNs.
        /// An optional domain argument is accepted.
        /// This method needs to be public as reflection is used to match the
        /// module name that is supplied via command line, to the actual method name.
        /// </summary>
        public static void sqlspns()
        {
            if (Var.ParsedArguments.ContainsKey("domain") && !string.IsNullOrEmpty(Var.ParsedArguments["domain"]))
            {
                Var.Arg1 = Var.ParsedArguments["domain"];
                // Use the domain supplied by the user.
                DomainSpns.GetSqlSpns(Var.Arg1);
            }
            else
            {
                // Use the current domain.
                DomainSpns.GetSqlSpns("");
            }
        }
    }

    /// <summary>
    /// The CheckEnumArguments class validates arguments which are required for modules.
    /// </summary>
    internal abstract class CheckEnumArguments
    {
        internal static bool Info()
        {
            if (Var.ParsedArguments.ContainsKey("host") && !string.IsNullOrEmpty(Var.ParsedArguments["host"]))
            {

                // Check for single or multiple hosts in "/host" or "/h" and assign into Var.sqlServers
                if (Var.ParsedArguments.ContainsKey("host"))
                {
                    // Var.SqlServers is an array which contains the single host, or comma-seperated hosts
                    // supplied into the "/host" variable 
                    Var.SqlServers = Var.ParsedArguments["host"]
                        .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    // Set the first host in the Var.SqlServers array to the initial connection host.
                    Var.SqlServer = Var.SqlServers[0];
                }
                
                // Optional timeout argument
                if (Var.ParsedArguments.ContainsKey("timeout") && !string.IsNullOrEmpty(Var.ParsedArguments["timeout"]))
                {
                    // If the user supplied a timeout value, set this.
                    Var.Timeout = Var.ParsedArguments["timeout"];
                }

                // Optional port argument
                if (Var.ParsedArguments.ContainsKey("port") && !string.IsNullOrEmpty(Var.ParsedArguments["port"]))
                {
                    // If the user supplied a port value, set this.
                    Var.Port = Var.ParsedArguments["port"];
                }
                else
                {
                    Var.Port = "1434";
                }
                
                return true;
            }
            else
            {
                Print.Error("Must supply one or more SQL servers (/h:, /host:)", true);
                // Go no further.
                return false;
            }
        }
    }
}
