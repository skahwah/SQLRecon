using System;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class Roles
    {
        // this will check to see if a user is part of the public role
        public void Public(SqlConnection con)
        {
            SqlCommand command = new SqlCommand("SELECT IS_SRVROLEMEMBER('public');", con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("\n[+] User is a member of public role");
            }
            else
            {
                Console.WriteLine("[!] User is NOT a member of public role\n");
            }
            reader.Close();
        } // end Public

        // this will check to see if a user is part of the sysadmin role
        public void SysAdmin(SqlConnection con)
        {
            SqlCommand command = new SqlCommand("SELECT IS_SRVROLEMEMBER('sysadmin');", con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("[+] User is a member of sysadmin role\n");
            }
            else
            {
                Console.WriteLine("[!] User is NOT a member of sysadmin role\n");
            }
            reader.Close();
        } // ned SysAdmin
    }
}

