using System;

namespace SQLRecon.Modules
{
    public class Help
    {
        public Help()
        {
            initialize();
        }

        // this returns the help menu to console
        public void initialize()
        {
            Console.WriteLine("");
            Console.WriteLine("SQLRecon v2.0");
            Console.WriteLine("github.com/skahwah/SQLRecon");
            Console.WriteLine("");

            Console.WriteLine("Authentication Type (-a):");

            Console.WriteLine("-a Windows - Use Windows authentication. This uses the current users token.");
            Console.WriteLine("\t[+] -s SERVERNAME | SQL server hostname");
            Console.WriteLine("\t[+] -d DATABASE | SQL server database name");
            Console.WriteLine("");

            Console.WriteLine("-a Local - Use local authentication. This requires the credentials for a local database user.");
            Console.WriteLine("\t[+] -s SERVERNAME | SQL server hostname");
            Console.WriteLine("\t[+] -d DATABASE | SQL server database name ");
            Console.WriteLine("\t[+] -u USERNAME | Username of local SQL user");
            Console.WriteLine("\t[+] -p PASSWORD | Password of local SQL user");
            Console.WriteLine("");

            Console.WriteLine("-a Azure - Use Azure AD domain username and password authentication. This requires the credentials for a domain user.");
            Console.WriteLine("\t[+] -s SERVERNAME | SQL server hostname");
            Console.WriteLine("\t[+] -d DATABASE | SQL server database name ");
            Console.WriteLine("\t[+] -r DOMAIN.COM | FQDN of Domain");
            Console.WriteLine("\t[+] -u USERNAME | Username of domain user");
            Console.WriteLine("\t[+] -p PASSWORD | Password of domain user");
            Console.WriteLine("");

            Console.WriteLine("Standard Modules (-m):");
            Console.WriteLine("\t[+] query -o QUERY | Execute an arbitary SQL query");
            Console.WriteLine("\t[+] whoami | See what user you are logged in as, mapped as and what roles exist");
            Console.WriteLine("\t[+] databases | Show all databases present on the SQL server");
            Console.WriteLine("\t[+] tables -o DATABASE | Show all tables in the database you specify");
            Console.WriteLine("\t[+] search -o KEYWORD | Search column names within tables of the database you are connected to");
            Console.WriteLine("\t[+] smb -o SHARE | Capture NetNTLMv2 hash");
            Console.WriteLine("\t------------------------------------------------------------");
            Console.WriteLine("\t| -> Command Execution (requires sysadmin role or similar) |");
            Console.WriteLine("\t------------------------------------------------------------");
            Console.WriteLine("\t[+] enablexp | Enable xp_cmdshell ");
            Console.WriteLine("\t[+] disablexp | Disable xp_cmdshell");
            Console.WriteLine("\t[+] xpcmd -o COMMAND | Execute an arbitary system command");
            Console.WriteLine("\t[+] enableole | Enable OLE Automation Procedures");
            Console.WriteLine("\t[+] disableole | Disable OLE Automation Procedures");
            Console.WriteLine("\t[+] olecmd -o COMMAND | Execute an arbitary system command");
            Console.WriteLine("\t[+] enableclr | Enable Custom CLR Assemblies");
            Console.WriteLine("\t[+] disableclr | Disable Custom CLR Assemblies");
            Console.WriteLine("\t[+] clr -o DLLPATH -f FUNCTION | Load and execute a .NET assembly within a custom stored procedure");
            Console.WriteLine("\t[+] agentstatus | Check to see if SQL agent is running and obtain jobs");
            Console.WriteLine("\t[+] agentcmd -o COMMAND | Execute an arbitary system command");
            Console.WriteLine("");

            Console.WriteLine("Linked SQL Server Modules (-m):");
            Console.WriteLine("\t[+] links | Enumerate any linked SQL servers");
            Console.WriteLine("\t[+] lquery -l LINKEDSERVERNAME -o QUERY | Execute an arbitary SQL query on the linked SQL server");
            Console.WriteLine("\t[+] lwhoami | See what user you are logged in as, mapped as and what roles exist on the linked SQL server");
            Console.WriteLine("\t[+] ldatabases -l LINKEDSERVERNAME | Show all databases present on the linked SQL server");
            Console.WriteLine("\t[+] ltables -l LINKEDSERVERNAME -o DATABASE | Show all tables in the supplied database on the linked SQL server");
            Console.WriteLine("\t[+] lsmb -l LINKEDSERVERNAME -o SHARE | Capture NetNTLMv2 hash from linked SQL server");
            Console.WriteLine("\t------------------------------------------------------------");
            Console.WriteLine("\t| -> Command Execution (requires sysadmin role or similar) |");
            Console.WriteLine("\t------------------------------------------------------------");
            Console.WriteLine("\t[+] lenablerpc -l LINKEDSERVERNAME | Enable RPC and RPC out on a linked SQL server");
            Console.WriteLine("\t[+] ldisablerpc -l LINKEDSERVERNAME | Disable RPC and RPC out on a linked SQL server");
            Console.WriteLine("\t[+] lenablexp -l LINKEDSERVERNAME | Enable xp_cmdshell on the linked SQL server");
            Console.WriteLine("\t[+] ldisablexp -l LINKEDSERVERNAME | Disable xp_cmdshell on the linked SQL server");
            Console.WriteLine("\t[+] lxpcmd -l LINKEDSERVERNAME -o COMMAND | Execute an arbitary system command on the linked SQL server");
            Console.WriteLine("\t[+] lenableole -l LINKEDSERVERNAME | Enable OLE Automation Procedures on the linked SQL server");
            Console.WriteLine("\t[+] ldisableole -l LINKEDSERVERNAME | Disable OLE Automation Procedures on the linked SQL server");
            Console.WriteLine("\t[+] lolecmd -l LINKEDSERVERNAME -o COMMAND | Execute an arbitary system command on the linked SQL server");
            Console.WriteLine("\t[+] lenableclr -l LINKEDSERVERNAME | Enable Custom CLR Assemblies on the linked SQL server");
            Console.WriteLine("\t[+] ldisableclr -l LINKEDSERVERNAME | Disable Custom CLR Assemblies on the linked SQL server");
            Console.WriteLine("\t[+] lagentstatus -l LINKEDSERVERNAME | Check to see if SQL agent is running and obtain jobs on the linked SQL server");
            Console.WriteLine("");

            Console.WriteLine("Impersonation Modules (-m):");
            Console.WriteLine("\t[+] impersonate | Enumerate any user accounts that can be impersonated");
            Console.WriteLine("\t[+] iwhoami | See what user you are logged in as, mapped as and what roles exist");
            Console.WriteLine("\t[+] iquery -i IMPERSONATEUSER -o QUERY | Execute an arbitary SQL query as an impersonated user");
            Console.WriteLine("\t------------------------------------------------------------");
            Console.WriteLine("\t| -> Command Execution (requires sysadmin role or similar) |");
            Console.WriteLine("\t------------------------------------------------------------");
            Console.WriteLine("\t[+] ienablexp -i IMPERSONATEUSER | Enable xp_cmdshell");
            Console.WriteLine("\t[+] idisablexp -i IMPERSONATEUSER | Disable xp_cmdshell");
            Console.WriteLine("\t[+] ixpcmd -i IMPERSONATEUSER -o COMMAND | Execute an arbitary system command");
            Console.WriteLine("\t[+] ienableole -i IMPERSONATEUSER | Enable OLE Automation Procedures");
            Console.WriteLine("\t[+] idisableole -i IMPERSONATEUSER | Disable OLE Automation Procedures");
            Console.WriteLine("\t[+] iolecmd -i IMPERSONATEUSER -o COMMAND | Execute an arbitary system command");
            Console.WriteLine("\t[+] ienablclr -i IMPERSONATEUSER | Enable CLR integration");
            Console.WriteLine("\t[+] idisablclr -i IMPERSONATEUSER | Disable CLR integration");
            Console.WriteLine("\t[+] iclr -i IMPERSONATEUSER -o DLLPATH -f FUNCTION | Load and execute a .NET assembly within a custom stored procedure");
            Console.WriteLine("\t[+] iagentstatus -i IMPERSONATEUSER | Check to see if SQL agent is running and obtain jobs");
            Console.WriteLine("\t[+] iagentcmd -i IMPERSONATEUSER -o COMMAND | Execute an arbitary system command");
        }
    }
}

