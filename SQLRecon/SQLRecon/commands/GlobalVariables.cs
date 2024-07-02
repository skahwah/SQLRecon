using System.Collections.Generic;
using System.Data.SqlClient;

namespace SQLRecon.Commands
{
    internal abstract class Var
    {
        internal static Dictionary<string, string> CoreCommands =>
            new()
            {
                {"a", "auth"},
                {"c", "command"},
                {"chain", "chain"},
                {"d", "domain"},
                {"debug","debug"},
                {"e", "enum"},
                {"h", "host"},
                {"i", "iuser"},
                {"l", "link"},
                {"m", "module"},
                {"o", "option"},
                {"p", "password"},
                {"s", "sccm"},
                {"u", "username"},
                {"t", "timeout"},
                {"v", "verbose"}
            };

        internal static Dictionary<string, int> EnumerationModulesAndArgumentCount =>
            new()
            {
                {"info", 1},
                {"sqlspns", 0},
            };

        internal static Dictionary<string, int[]> SccmModulesAndArgumentCount
        {
            get
            {
                return new Dictionary<string, int[]>()
                {
                    /* Module Description:

                     Dictionary Key -> Module name
                     Dictionary Value -> Number of required arguments for:

                     - Standard modules in array position 0
                     - Impersonation modules in array position 1

                     The following modules have no Impersonation support, and have been set to -1:
                      - decryptcredentials
                     */
                    {"credentials", new[] { 0, 1 }},
                    {"decryptcredentials", new[] { 0, -1 }},
                    {"logons", new[] { 0, 1 }},
                    {"sites", new[] { 0, 1 }},
                    {"taskdata", new[] { 0, 1 }},
                    {"tasklist", new[] { 0, 1 }},
                    {"users", new[] { 0, 1 }},
                    {"addadmin", new[] { 2, 3 }},
                    {"removeadmin", new[] { 2, 3 }},
                };
            }
        }
        
        internal static Dictionary<string, int[]> SqlModulesAndArgumentCount
        {
            get 
            {
                return new Dictionary<string, int[]>()
                {
                    /* Module Description:
                     
                     Dictionary Key -> Module name
                     Dictionary Value -> Number of required arguments for:
                      
                     - Standard modules in array position 0
                     - Impersonation modules in array position 1
                     - Linked modules in array position 2
                                          
                     The following modules have no Linked or Chain support, and have been set to -1:
                      - disablerpc
                      - enablerpc
                     */
                    
                    {"agentstatus", new[] { 0, 1, 1 }},
                    {"checkrpc", new[] { 0, 1, 1 }},
                    {"databases", new[] { 0, 1, 1 }},
                    {"disableclr", new[] { 0, 1, 1 }},
                    {"disableole", new[] { 0, 1, 1 }},
                    {"disablexp", new[] { 0, 1, 1 }},
                    {"enableclr", new[] { 0, 1, 1 }},
                    {"enableole", new[] { 0, 1, 1 }},
                    {"enablexp", new[] { 0, 1, 1 }},
                    {"info", new[] { 0, 0, 0 }},
                    {"impersonate", new[] { 0, 0, 0 }},
                    {"links", new[] { 0, 1, 2}},
                    {"users", new[] { 0, 1, 2 }},
                    {"whoami", new[] { 0, 1, 2 }},
                    {"agentcmd", new[] { 1, 2, 2 }},
                    {"disablerpc", new[] { 1, 2, -1 }},
                    {"enablerpc", new[] { 1, 2, -1 }},
                    {"olecmd", new[] { 1, 2, 2 }},
                    {"query", new[] { 1, 2, 2 }},
                    {"search", new[] { 1, 2, 3 }},
                    {"smb", new[] { 1, 2, 2 }},
                    {"tables", new[] { 1, 2, 2 }},
                    {"xpcmd", new[] { 1, 2, 2 }},
                    {"adsi", new[] { 2, 3, 3 }},
                    {"clr", new[] { 2, 3, 3}},
                    {"columns", new[] { 2, 3, 3 }},
                    {"rows", new[] { 2, 3, 3 }}
                };
            }
        }
        
        internal static string Arg1 { get; set; }

        internal static string Arg2 { get; set; }

        internal static string Arg3 { get; set; }

        internal static string AuthenticationType { get; set; }

        internal static string Context { get; set; }

        internal static SqlConnection Connect { get; set; }

        internal static string Database { get; set; } = "master";

        internal static bool Debug { get; set; }

        internal static string Domain { get; set; }

        internal static string EnumerationModule { get; set; }

        internal static string Impersonate { get; set; }

        internal static string LinkedSqlServer { get; set; }

        internal static string[] LinkedSqlServers { get; set; }

        internal static string[] LinkedSqlServersChain { get; set; }

        internal static bool LinkedSqlServerChain { get; set; }

        internal static string Module { get; set; }

        internal static Dictionary<string, string> ParsedArguments { get; set; }

        internal static string Password { get; set; }

        internal static string Port { get; set; } = "1433";

        internal static string SccmModule { get; set; }

        internal static string SqlServer { get; set; }

        internal static string[] SqlServers { get; set; }

        internal static string Username { get; set; }

        internal static string Timeout { get; set; } = "3";

        internal static bool Verbose { get; set; }
    }
}