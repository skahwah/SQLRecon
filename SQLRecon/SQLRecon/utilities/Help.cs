using System;
using System.Collections.Generic;
using System.Linq;

namespace SQLRecon.Utilities
{
    internal class Help
    {
        /// <summary>
        /// The Help constructor prints the help menu to console.
        /// </summary>
        internal Help()
        {
            Console.WriteLine("");
            Console.WriteLine("SQLRecon");
            Console.WriteLine("Version: 3.8");
            Console.WriteLine("Wiki: github.com/skahwah/SQLRecon");
            
            Console.WriteLine("");
            _border(90);
            Console.WriteLine("[+] Enumeration Modules (/e:, /enum:) do not require authentication to be supplied.");
            _border(90);
            Console.WriteLine("");
            Console.WriteLine("Info    - Show information about the SQL server");
            _nested(10, "/h:, /host    -> SQL server hostname or IP. Multiple hosts supported.");
            _nested(10, "/port:        -> (OPTIONAL) Defaults to 1434 (UDP).");
            _nested(10, "/t:, timeout: -> (OPTIONAL) Defaults to 3s.");
            Console.WriteLine("SqlSpns - Use the current user token to enumerate the AD domain for MSSQL SPNs.");
            _nested(10, "/d:, /domain: -> (OPTIONAL) NETBIOS name or FQDN of domain.");
            
            Console.WriteLine("");
            _border(90);
            Console.WriteLine("[+] SQL Authentication Providers (/a:, /auth:) ");
            _border(90);
            Console.WriteLine();
            Console.WriteLine("WinToken   - Use the current users token to authenticate against the SQL database.");
            _nested(13, "/h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.");
            Console.WriteLine("WinDomain  - Use AD credentials to authenticate against the SQL database.");
            _nested(13, "/h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.");
            _nested(13, "/d:, /domain:   -> NETBIOS name or FQDN of domain.");
            _nested(13, "/u:, /username: -> Username for domain user.");
            _nested(13, "/p:, /password: -> Password for domain user.");
            Console.WriteLine("Local      - Use local SQL credentials to authenticate against the SQL database.");
            _nested(13, "/h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.");
            _nested(13, "/u:, /username: -> Username for local SQL user.");
            _nested(13, "/p:, /password: -> Password for local SQL user.");
            Console.WriteLine("EntraID    - Use Azure Entra ID credentials to authenticate against the Azure SQL database.");
            _nested(13, "/h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.");
            _nested(13, "/d:, /domain:   -> FQDN of domain (DOMAIN.COM).");
            _nested(13, "/u:, /username: -> Username for domain user. ");
            _nested(13, "/p:, /password: -> Password for domain user. ");
            Console.WriteLine("AzureLocal - Use local SQL credentials to authenticate against the Azure SQL database.");
            _nested(13, "/h:, /host:     -> SQL server hostname or IP. Multiple hosts supported.");
            _nested(13, "/u:, /username: -> Username for local SQL user.");
            _nested(13, "/p:, /password: -> Password for local SQL user.");
            Console.WriteLine("OPTIONAL   - The following arguments are supported by all providers and modules.");
            _nested(13, "/database:      -> (OPTIONAL) SQL server database name, defaults to 'master'.");
            _nested(13, "/debug          -> (OPTIONAL) Display queries used by a module, but do not execute.");
            _nested(13, "/port:          -> (OPTIONAL) Defaults to 1433 (TCP).");
            _nested(13, "/t:, timeout:   -> (OPTIONAL) Defaults to 3s.");
            _nested(13, "/v, verbose     -> (OPTIONAL) Display and execute queries used by a module.");
            
            Console.WriteLine("");
            _border(90);
            Console.WriteLine("[+] SQL Modules (/m:, /module:) require an authentication provider to be supplied.");
            _border(90);
            Console.WriteLine("");
            Console.WriteLine("[M] - The module supports execution against multiple comma separated SQL servers supplied in /h:, /host:");
            Console.WriteLine("[I] - The module supports execution against SQL servers with a impersonated user (/i:, /iuser:)");
            Console.WriteLine("[L] - The module supports execution against multiple comma separated linked SQL server supplied in /l:, /link:");
            Console.WriteLine("[C] - The module supports execution against the final linked SQL server in a chain.");
            _nested(6, "/l:, link -> The linked SQL server path separated by commas.");
            _nested(6, "/chain    -> Supply this flag to enable chained execution mode.");
            Console.WriteLine("[*] - The module requires a privileged context to execute.");
            Console.WriteLine("");

            Dictionary<string,string> dict = new Dictionary<string, string>()
            {
                { "CheckRpc","[M,I,L,C] Obtain a list of linked servers and their RPC status." },
                { "Databases","[M,I,L,C] Display all databases." },
                { "Impersonate","[M,I,L,C] Enumerate user accounts that can be impersonated." },
                { "Info","[M,I,L,C] Show information about the SQL server." },
                { "Links","[M,I,L,C] Enumerate linked SQL servers." },
                { "Users","[M,I,L,C] Display what user accounts and groups can authenticate against the database." },
                { "Whoami","[M,I,L,C] Display your privileges." },
                { "Query /c:QUERY","[M,I,L,C] Execute a SQL query." },
                { "Smb /unc:UNC_PATH","[M,I,L,C] Capture NetNTLMv2 hash." },
                { "Columns /db:DATABASE /table:TABLE","[M,I,L,C] Display all columns in the supplied database and table." },
                { "Rows /db:DATABASE /table:TABLE","[M,I,L,C] Display the number of rows in the supplied database table." },
                { "Search /keyword:KEYWORD","[M,I,L,C] Search column names in the supplied table of the database you are connected to." },
                { "Tables /db:DATABASE","[M,I,L,C] Display all tables in the supplied database." },
                { "EnableRpc /rhost:LINKED_HOST","[*,M,I] Enable RPC and RPC out on a linked server." },
                { "EnableClr","[*,M,I,L,C] Enable CLR integration." },
                { "EnableOle","[*,M,I,L,C] Enable OLE automation procedures." },
                { "EnableXp","[*,M,I,L,C] Enable xp_cmdshell." },
                { "DisableRpc /rhost:LINKED_HOST","[*,M,I] Disable RPC and RPC out on a linked server." },
                { "DisableClr","[*,M,I,L,C] Disable CLR integration." },
                { "DisableOle","[*,M,I,L,C] Disable OLE automation procedures." },
                { "DisableXp","[*,M,I,L,C] Disable xp_cmdshell." },
                { "AgentStatus","[*,M,I,L,C] Display if SQL agent is running and obtain agent jobs." },
                { "AgentCmd /c:COMMAND","[*,M,I,L,C] Execute a system command using agent jobs." },
                { "Adsi /adsi:SERVER_NAME /lport:LOCAL_PORT","[*,M,I,L,C] Obtain cleartext ADSI credentials from a linked ADSI server." },
                { "Clr /dll:DLL /function:FUNCTION","[*,M,I,L,C] Load and execute a .NET assembly in a custom stored procedure." },
                { "OleCmd /c:COMMAND /subsystem:(OPTIONAL","[*,M,I,L,C] Execute a system command using OLE automation procedures." },
                { "XpCmd /c:COMMAND","[*,M,I,L,C] Execute a system command using xp_cmdshell." }
            };
            
            _printDictionary(dict);
            
            Console.WriteLine("");
            _border(90);
            Console.WriteLine("SCCM Modules (/s:, /sccm:)");
            _border(90);
            dict = new Dictionary<string, string>()
            {
                { "Users", "[I] Display all SCCM users." },
                { "Sites", "[I] Display all other sites with data stored." },
                { "Logons", "[I] Display all associated SCCM clients and the last logged in user." },
                { "Credentials", "[I] Display encrypted credentials vaulted by SCCM." },
                { "TaskList", "[I] Display all task sequences, but do not access the task data contents." },
                { "TaskData", "[I] Decrypt all task sequences to plaintext." },
                { "[*] DecryptCredentials", "[*] Decrypt an SCCM credential blob. Must execute in a high-integrity or SYSTEM process on the SCCM server." },
                { "[*] AddAdmin /user:DOMAIN\\USERNAME /sid:SID", "[*, I] Elevate a supplied account to a 'Full Administrator' in SCCM." },
                { "[*] RemoveAdmin /user:ADMIN_ID /remove:STRING", "[*, I] Removes privileges of a user, or remove a user entirely from the SCCM database." }
            };
            _printDictionary(dict);
        }

        private void _padSpaces(string column1, int spaces, string delimeter, string column2)
        {
            string result = column1.PadRight(spaces, ' ') + delimeter + column2;
            Console.WriteLine(result);
        }
        
        private void _printDictionary(Dictionary<string, string> dict, bool nested = false)
        {
            // Determine the longest key in the dictionary
            int padding = dict.Max(t => t.Key.Length);
            string delimeter = " - ";
            
            if (nested)
            {
                foreach (KeyValuePair<string, string> entry in dict)
                {
                    _padSpaces(entry.Key, padding, delimeter, entry.Value);

                    if (entry.Key.StartsWith("/"))
                    {
                        delimeter = " -> ";
                        _padSpaces(entry.Key, padding + 2, delimeter, entry.Value);
                    }
                    
                }
            }
            else
            {
                foreach (KeyValuePair<string, string> entry in dict)
                {
                    _padSpaces(entry.Key, padding, delimeter, entry.Value);
                }
            }
        }
        
        /// <summary>
        /// The _nested method will print a nested string with left space padding.
        /// </summary>
        /// <param name="spaces"></param>
        /// <param name="str"></param>
        private void _nested(int spaces, string str)
        {
            string space = new string (' ', spaces);
            Console.WriteLine(string.Format($"{space}{str}"));
        }
        
        /// <summary>
        /// The _border method will print hyphens.
        /// </summary>
        /// <param name="dashes"></param>
        private void _border(int dashes)
        {
            string dash = new string ('-', dashes);
            Console.WriteLine(dash);
        }
    }
}

