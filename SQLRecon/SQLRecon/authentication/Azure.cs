using System;
using System.Data.SqlClient;

namespace SQLRecon.Auth
{
    public class AzureAuth
    {
        // this handles domain authentication to Azure based MS SQL databases
        public SqlConnection Send(String sqlServer, String database, String domain, String user, String pass)
        {
            user = user + "@" + domain;
            String conString = "Server = " + sqlServer + "; Database = " + database + ";  Authentication=Active Directory Password; TrustServerCertificate=True; user id=" + user + "; password=" + pass + ";";
            TestAuthentication TestAuthentication = new TestAuthentication();
            return TestAuthentication.Send(conString, user, sqlServer);
        } 
    }
}
