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
            Console.WriteLine("SQLRecon v1.2");
            Console.WriteLine("");

            Console.WriteLine("Examples");
            Console.WriteLine("\tSQLRecon.exe -a Windows -s SQL01 -d Master -m mapped");
            Console.WriteLine("\tSQLRecon.exe -a Local -s SQL02 -d Master -u sa -p Password123 -m query -q \"SELECT @@VERSION;\"");
            Console.WriteLine("\tSQLRecon.exe -a Local -s SQL01 -d Master -u map -p Password123 -m ienableole -i sa");
            Console.WriteLine("\tSQLRecon.exe -a Local -s SQL01 -d Master -u sa -p Password123 -m lquery -l SQL02 -q \"SELECT @@VERSION;\"");
            Console.WriteLine("");

            Console.WriteLine("Authentication Type (-a)");
            Console.WriteLine("");

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

            Console.WriteLine("Standard Modules (-m)");
            Console.WriteLine("\t[+] query -o QUERY | Execute an arbitary SQL query");
            Console.WriteLine("\t[+] whoami | See what user you are logged in as");
            Console.WriteLine("\t[+] mapped | See what user you are mapped to");
            Console.WriteLine("\t[+] roles | Enumerate if the user has public and/or sysadmin roles mapped");
            Console.WriteLine("\t[+] databases | Show all databases present on the SQL server");
            Console.WriteLine("\t[+] tables | Show all tables in the database you are connected to");
            Console.WriteLine("\t[+] search -o KEYWORD | Search column names within tables of the database you are connected to.");
            Console.WriteLine("\t[+] smb -o SHARE | Capture NetNTLMv2 hash");
            Console.WriteLine("\t[+] enablexp | Enable xp_cmdshell (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] disablexp | Disable xp_cmdshell (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] xpcmd -o COMMAND | Execute an arbitary system command (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] enableole | Enable OLE Automation Procedures (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] disableole | Disable OLE Automation Procedures (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] olecmd -o COMMAND | Execute an arbitary system command (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] enableclr | Enable Custom CLR Assemblies (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] disableclr | Disable Custom CLR Assemblies (requires sysadmin role or similar)");
            Console.WriteLine("");

            Console.WriteLine("Linked SQL Server Modules (-m)");
            Console.WriteLine("\t[+] links | Enumerate any linked SQL servers");
            Console.WriteLine("\t[+] lquery -l LINKEDSERVERNAME -o QUERY | Execute an arbitary SQL query on the linked SQL server");
            Console.WriteLine("\t[+] lwhoami | See what user you are logged in as on the linked SQL server");
            Console.WriteLine("\t[+] lroles | Enumerate if the linked SQL server user has public and/or sysadmin roles mapped");
            Console.WriteLine("\t[+] ldatabases -l LINKEDSERVERNAME | Show all databases present on the linked SQL server");
            Console.WriteLine("\t[+] ltables -l LINKEDSERVERNAME -o DATABASE | Show all tables in the supplied database on the linked SQL server");
            Console.WriteLine("\t[+] lsmb -l LINKEDSERVERNAME -o SHARE | Capture NetNTLMv2 hash from linked SQL server");

            Console.WriteLine("");

            Console.WriteLine("Impersonation Modules (-m)");
            Console.WriteLine("\t[+] impersonate | Enumerate any user accounts that can be impersonated");
            Console.WriteLine("\t[+] iquery -i IMPERSONATEUSER -o QUERY | Execute an arbitary SQL query as an impersonated user");
            Console.WriteLine("\t[+] ienablexp -i IMPERSONATEUSER | Enable xp_cmdshell (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] idisablexp -i IMPERSONATEUSER | Disable xp_cmdshell (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] ixpcmd -i IMPERSONATEUSER -o COMMAND | Execute an arbitary system command (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] ienableole -i IMPERSONATEUSER | Enable OLE Automation Procedures (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] idisableole -i IMPERSONATEUSER | Disable OLE Automation Procedures (requires sysadmin role or similar)");
            Console.WriteLine("\t[+] iolecmd -i IMPERSONATEUSER -o COMMAND | Execute an arbitary system command (requires sysadmin role or similar)");
            Console.WriteLine("");
        }
    }
}

