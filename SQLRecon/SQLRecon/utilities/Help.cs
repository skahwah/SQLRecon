using System;

namespace SQLRecon.Utilities
{
    internal class Help
    {

        /// <summary>
        /// The Help constructor prints the help menu to console.
        /// </summary>
        public Help()
        {
            Console.WriteLine("");
            Console.WriteLine("SQLRecon");
            Console.WriteLine("Version: 3.3.0");
            Console.WriteLine("github.com/skahwah/SQLRecon");

            Console.WriteLine("");
            Console.WriteLine("Modules starting with '[*]' require sysadmin role or a similar privileged context");

            Console.WriteLine("");
            Console.WriteLine("---------------------------------------------------------------------------------------");
            Console.WriteLine("\tEnumeration Modules (/e:, /enum:) do not require authentication to be supplied:");
            Console.WriteLine("---------------------------------------------------------------------------------------");

            Console.WriteLine("SqlSpns - Use the current user token to enumerate the current AD domain for MSSQL SPNs");
            var table = new TablePrinter("", "", "");
            table.AddRow("\t/d:, /domain:", "|", "(OPTIONAL) NETBIOS name (DOMAIN) or FQDN of domain (DOMAIN.COM)");
            table.Print();

            Console.WriteLine("");
            Console.WriteLine("--------------------------------------------------------------------------------------");
            Console.WriteLine("\tAuthentication Providers (/a:, /auth:) set the SQL server authentication type:");
            Console.WriteLine("--------------------------------------------------------------------------------------");

            Console.WriteLine("WinToken - Use the current users token to authenticate against the SQL database");
            table = new TablePrinter("", "", "");
            table.AddRow("\t/h:, /host:", "|", "SQL server hostname or IP");
            table.AddRow("\t/database:", "|", "(OPTIONAL) SQL server database name, defaults to 'master'");
            table.AddRow("\t/port:", "|", "(OPTIONAL) Defaults to 1433");
            table.Print();

            Console.WriteLine("");
            table = new TablePrinter("", "", "");
            Console.WriteLine("WinDomain - Use AD credentials to authenticate against the SQL database");
            table.AddRow("\t/h:, /host:", "|", "SQL server hostname or IP");
            table.AddRow("\t/d:, /domain:", "|", "NETBIOS name (DOMAIN) or FQDN of domain (DOMAIN.COM)");
            table.AddRow("\t/u:, /username:", "|", "Username for domain user");
            table.AddRow("\t/p:, /password:", "|", "Password for domain user");
            table.AddRow("\t/database:", "|", "(OPTIONAL) SQL server database name, defaults to 'master'");
            table.AddRow("\t/port:", "|", "(OPTIONAL) Defaults to 1433");
            table.Print();

            Console.WriteLine("");
            table = new TablePrinter("", "", "");
            Console.WriteLine("Local - Use local SQL credentials to authenticate against the SQL database");
            table.AddRow("\t/h:, /host:", "|", "SQL server hostname or IP");
            table.AddRow("\t/u:, /username:", "|", "Username for local SQL user");
            table.AddRow("\t/p:, /password:", "|", "Password for local SQL user");
            table.AddRow("\t/database:", "|", "(OPTIONAL) SQL server database name, defaults to 'master'");
            table.AddRow("\t/port:", "|", "(OPTIONAL) Defaults to 1433");
            table.Print();

            Console.WriteLine("");
            table = new TablePrinter("", "", "");
            Console.WriteLine("AzureAD - Use Azure AD credentials to authenticate against the Azure SQL database");
            table.AddRow("\t/h:, /host:", "|", "SQL server hostname or IP");
            table.AddRow("\t/d:, /domain:", "|", "FQDN of domain (DOMAIN.COM)");
            table.AddRow("\t/u:, /username:", "|", "Username for domain user");
            table.AddRow("\t/p:, /password:", "|", "Password for domain user");
            table.AddRow("\t/database:", "|", "(OPTIONAL) SQL server database name, defaults to 'master'");
            table.Print();

            Console.WriteLine("");
            table = new TablePrinter("", "", "");
            Console.WriteLine("AzureLocal - Use local SQL credentials to authenticate against the Azure SQL database");
            table.AddRow("\t/h:, /host:", "|", "SQL server hostname or IP");
            table.AddRow("\t/u:, /username:", "|", "Username for local SQL user");
            table.AddRow("\t/p:, /password:", "|", "Password for local SQL user");
            table.AddRow("\t/database:", "|", "(OPTIONAL) SQL server database name, defaults to 'master'");
            table.AddRow("\t/port:", "|", "(OPTIONAL) Defaults to 1433");
            table.Print();

            Console.WriteLine("");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("\tStandard Modules (/m:, /module:) are executed against a single instance of SQL server:");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            
            table = new TablePrinter("", "", "");
            table.AddRow("\tInfo", "|", "Show information about the SQL server");
            table.AddRow("\tQuery /c:QUERY", "|", "Execute a SQL query");
            table.AddRow("\tWhoami", "|", "Display what user you are logged in as, mapped as and what roles exist");
            table.AddRow("\tUsers", "|", "Display what user accounts and groups can authenticate against the database");
            table.AddRow("\tDatabases", "|", "Display all databases");
            table.AddRow("\tTables /db:DATABASE", "|", "Display all tables in the supplied database");
            table.AddRow("\tColumns /db:DATABASE /table:TABLE", "|", "Display all columns in the supplied database and table");
            table.AddRow("\tRows /db:DATABASE /table:TABLE", "|", "Display the number of rows in the supplied database table");
            table.AddRow("\tSearch /keyword:KEYWORD", "|", "Search column names in the supplied table of the database you are connected to");
            table.AddRow("\tSmb /rhost:UNC_PATH", "|", "Capture NetNTLMv2 hash");
            table.AddRow("\tImpersonate", "|", "Enumerate user accounts that can be impersonated");
            table.AddRow("\tLinks", "|", "Enumerate linked SQL servers");
            table.AddRow("\tCheckRpc", "|", "Obtain a list of linked servers and their RPC status");
            table.AddRow("\t[*] EnableRpc /rhost:LINKED_HOST", "|", "Enable RPC and RPC out on a linked server");
            table.AddRow("\t[*] DisableRpc /rhost:LINKED_HOST", "|", "Disable RPC and RPC out on a linked server");
            table.AddRow("\t[*] EnableXp", "|", "Enable xp_cmdshell");
            table.AddRow("\t[*] DisableXp", "|", "Disable xp_cmdshell");
            table.AddRow("\t[*] XpCmd /c:COMMAND", "|", "Execute a system command using xp_cmdshell");
            table.AddRow("\t[*] EnableOle", "|", "Enable OLE automation procedures");
            table.AddRow("\t[*] DisableOle", "|", "Disable OLE automation procedures");
            table.AddRow("\t[*] OleCmd /c:COMMAND", "|", "Execute a system command using OLE automation procedures");
            table.AddRow("\t[*] EnableClr", "|", "Enable CLR integration");
            table.AddRow("\t[*] DisableClr", "|", "Disable CLR integration");
            table.AddRow("\t[*] Clr /dll:DLL /function:FUNCTION", "|", "Load and execute a .NET assembly in a custom stored procedure");
            table.AddRow("\t[*] AgentStatus", "|", "Display if SQL agent is running and obtain agent jobs");
            table.AddRow("\t[*] AgentCmd /c:COMMAND", "|", "Execute a system command using agent jobs");
            table.AddRow("\t[*] Adsi /rhost:ADSI_SERVER_NAME /lport:LDAP_SERVER_PORT", "|", "Obtain cleartext ADSI credentials from a linked ADSI server");
            table.Print();

            Console.WriteLine("");
            Console.WriteLine("------------------------------------------------------------------------------------------");
            Console.WriteLine("\tLinked Modules (/m:, /module:) are executed on a linked SQL server (/l:, /lhost:):");
            Console.WriteLine("------------------------------------------------------------------------------------------");
            
            table = new TablePrinter("", "", "");
            table.AddRow("\tlQuery /l:LINKED_HOST /c:QUERY", "|", "Execute a SQL query");
            table.AddRow("\tlWhoami /l:LINKED_HOST", "|", "Display what user you are logged in as, mapped as and what roles exist");
            table.AddRow("\tlUsers /l:LINKED_HOST", "|", "Display what user accounts and groups can authenticate against the database");
            table.AddRow("\tlDatabases /l:LINKED_HOST", "|", "Display all databases");
            table.AddRow("\tlTables /l:LINKED_HOST /db:DATABASE", "|", "Display all tables in the supplied database");
            table.AddRow("\tlColumns /l:LINKED_HOST /db:DATABASE /table:TABLE", "|", "Display all columns in the supplied database and table");
            table.AddRow("\tlRows /l:LINKED_HOST /db:DATABASE /table:TABLE", "|", "Display the number of rows in the supplied database and table");
            table.AddRow("\tlSearch /l:LINKED_HOST /db:DATABASE /keyword:KEYWORD", "|", "Search column names in the supplied table of the database you are connected to");
            table.AddRow("\tlSmb /l:LINKED_HOST /rhost:UNC_PATH", "|", "Capture NetNTLMv2 hash");
            table.AddRow("\tlLinks /l:LINKED_HOST", "|", "Enumerate linked SQL servers on a linked SQL server");
            table.AddRow("\tlCheckRpc /l:LINKED_HOST", "|", "Obtain a list of linked servers on the linked server and their RPC status");
            table.AddRow("\t[*] lEnableXp /l:LINKED_HOST", "|", "Enable xp_cmdshell");
            table.AddRow("\t[*] lDisableXp /l:LINKED_HOST", "|", "Disable xp_cmdshell");
            table.AddRow("\t[*] lXpCmd /l:LINKED_HOST /c:COMMAND", "|", "Execute a system command using xp_cmdshell");
            table.AddRow("\t[*] lEnableOle /l:LINKED_HOST", "|", "Enable OLE automation procedures");
            table.AddRow("\t[*] lDisableOle /l:LINKED_HOST", "|", "Disable OLE automation procedures");
            table.AddRow("\t[*] lOleCmd /l:LINKED_HOST /c:COMMAND", "|", "Execute a system command using OLE automation procedures");
            table.AddRow("\t[*] lEnableClr /l:LINKED_HOST", "|", "Enable CLR integration");
            table.AddRow("\t[*] lDisableClr /l:LINKED_HOST", "|", "Disable CLR integration");
            table.AddRow("\t[*] lClr /l:LINKED_HOST /dll:DLL /function:FUNCTION", "|", "Load and execute a .NET assembly in a custom stored procedure");
            table.AddRow("\t[*] lAgentStatus /l:LINKED_HOST", "|", "Display if SQL agent is running and obtain agent jobs");
            table.AddRow("\t[*] lAgentCmd /l:LINKED_HOST /c:COMMAND", "|", "Execute a system command using agent jobs");
            table.AddRow("\t[*] lAdsi /l:LINKED_HOST /rhost:ADSI_SERVER_NAME /lport:LDAP_SERVER_PORT", "|", "Obtain cleartext ADSI credentials from a double-linked ADSI server");
            table.Print();

            Console.WriteLine("");
            Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine("\tImpersonation Modules (/m:, /module:) are executed against a single instance of SQL server using impersonation (/i:, /iuser:):");
            Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------");
            
            table = new TablePrinter("", "", "");
            table.AddRow("\tiQuery /i:IMPERSONATE_USER /c:QUERY", "|", "Execute a SQL query");
            table.AddRow("\tiWhoami /i:IMPERSONATE_USER", "|", "Display what user you are logged in as, mapped as and what roles exist");
            table.AddRow("\tiUsers /i:IMPERSONATE_USER", "|", "Display what user accounts and groups can authenticate against the database");
            table.AddRow("\tiDatabases /i:IMPERSONATE_USER", "|", "Display all databases");
            table.AddRow("\tiTables /i:IMPERSONATE_USER /db:DATABASE", "|", "Display all tables in the supplied database");
            table.AddRow("\tiColumns /i:IMPERSONATE_USER /db:DATABASE /table:TABLE", "|", "Show all columns in the database and table you specify");
            table.AddRow("\tiRows /i:IMPERSONATE_USER /db:DATABASE /table:TABLE", "|", "Display the number of rows in the database and table you specify");
            table.AddRow("\tiSearch /i:IMPERSONATE_USER /keyword:KEYWORD", "|", "Search column names in the supplied table of the database you are connected to");
            table.AddRow("\tiLinks /i:IMPERSONATE_USER", "|", "Enumerate linked SQL servers");
            table.AddRow("\tiCheckRpc /i:IMPERSONATE_USER", "|", "Obtain a list of linked servers and their RPC status");
            table.AddRow("\t[*] iEnableRpc /i:IMPERSONATE_USER /rhost:LINKED_HOST", "|", "Enable RPC and RPC out on a linked server");
            table.AddRow("\t[*] iDisableRpc /i:IMPERSONATE_USER /rhost:LINKED_HOST", "|", "Disable RPC and RPC out on a linked server");
            table.AddRow("\t[*] iEnableXp /i:IMPERSONATE_USER", "|", "Enable xp_cmdshell");
            table.AddRow("\t[*] iDisableXp /i:IMPERSONATE_USER", "|", "Disable xp_cmdshell");
            table.AddRow("\t[*] iXpCmd /i:IMPERSONATE_USER /c:COMMAND", "|", "Execute a system command using xp_cmdshell");
            table.AddRow("\t[*] iEnableOle /i:IMPERSONATE_USER", "|", "Enable OLE automation procedures");
            table.AddRow("\t[*] iDisableOle /i:IMPERSONATE_USER", "|", "Disable OLE automation procedures");
            table.AddRow("\t[*] iOleCmd /i:IMPERSONATE_USER /c:COMMAND", "|", "Execute a system command using OLE automation procedures");
            table.AddRow("\t[*] iEnableClr /i:IMPERSONATE_USER", "|", "Enable CLR integration");
            table.AddRow("\t[*] iDisableClr /i:IMPERSONATE_USER", "|", "Disable CLR integration");
            table.AddRow("\t[*] iClr /i:IMPERSONATE_USER /dll:DLL /function:FUNCTION", "|", "Load and execute a .NET assembly in a custom stored procedure");
            table.AddRow("\t[*] iAgentStatus /i:IMPERSONATE_USER", "|", "Display if SQL agent is running and obtain agent jobs");
            table.AddRow("\t[*] iAgentCmd /i:IMPERSONATE_USER /c:COMMAND", "|", "Execute a system command using agent jobs");
            table.AddRow("\t[*] iAdsi /i:IMPERSONATE_USER /rhost:ADSI_SERVER_NAME /lport:LDAP_SERVER_PORT", "|", "Obtain cleartext ADSI credentials from a linked ADSI server");
            table.Print();

            Console.WriteLine("");
            Console.WriteLine("-----------------------------------------------------------------------------");
            Console.WriteLine("\tSCCM Modules (/m:, /module:) execute SCCM database-specific commands:");
            Console.WriteLine("-----------------------------------------------------------------------------");

            table = new TablePrinter("", "", "");
            table.AddRow("\tsDatabases", "|", "Display all SCCM databases");
            table.AddRow("\tsUsers", "|", "Display all SCCM users");
            table.AddRow("\tsSites", "|", "Display all other sites with data stored");
            table.AddRow("\tsLogons /option:OPTIONAL_FILTER", "|", "Display all associated SCCM clients and the last logged in user");
            table.AddRow("\tsTaskList", "|", "Display all task sequences, but do not access the task data contents");
            table.AddRow("\tsTaskData", "|", "Decrypt all task sequences to plaintext");
            table.AddRow("\tsCredentials", "|", "Display encrypted credentials vaulted by SCCM");
            table.AddRow("\t[*] sDecryptCredentials", "|", "Attempt to decrypt recovered SCCM credential blobs. Must be ran in a high-integrty or SYSTEM process on an SCCM server");
            table.AddRow("\t[*] sAddAdmin /user:DOMAIN\\USERNAME /sid:SID", "|", "This will elevate a supplied account to a 'Full Administrator' in SCCM");
            table.AddRow("\t[*] sRemoveAdmin /user:ADMIN_ID /remove:REMOVE_STRING", "|", "Removes privileges of a user, or remove a user entirely from the SCCM database");
            table.Print();

            Console.WriteLine("");
        }
    }
}

