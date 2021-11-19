using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using SQLRecon.Auth;

namespace SQLRecon.Auth
{
    public class LocalAuth
    {
        // this handles local authentication to MS SQL databases
        public SqlConnection Send(String sqlServer, String database, String user, String pass)
        {
            //Console.WriteLine("[+] Local Authentication Selected");
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security=false; user id=" + user + "; password=" + pass + ";";

            TestAuthentication TestAuthentication = new TestAuthentication();
            return TestAuthentication.Send(conString, user, sqlServer);
        } // end Send
    }
}
