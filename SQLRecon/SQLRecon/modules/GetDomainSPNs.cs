using System;
using System.Collections.Generic;
using System.Security.Principal;

using SQLRecon.utilities;

namespace SQLRecon.Modules
{
    public static class DomainSPNs
    {
        public static void GetMSSQLSPNs(string domain = null)
        {
            Console.Write("Looking for MSSQL SPNs... ");
            
            var searcher = string.IsNullOrWhiteSpace(domain)
                ? new DomainSearcher()
                : new DomainSearcher($"LDAP://{domain}");
            
            var ldap = new Ldap(searcher);
            
            const string filter = "(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))";
            var properties = new[] { "cn", "samaccountname", "objectsid", "serviceprincipalname", "lastlogon" };

            var results = ldap.ExecuteQuery(filter, properties);
            var instances = new List<SqlInstance>();

            foreach (var result in results.Values)
            {
                foreach (string spn in result["serviceprincipalname"])
                {
                    var sqlInstance = new SqlInstance();
                    
                    // parse the SPN string
                    // MSSQLSvc/sql-1.testlab.local:1433
                    // MSSQLSvc/sql-1.testlab.local

                    var i1 = spn.IndexOf('/');
                    
                    var serviceName = spn.Substring(0, i1);
                    var instance = spn.Substring(i1 + 1, spn.Length - i1 - 1);

                    var i2 = instance.IndexOf(':');

                    var computerName = i2 == -1
                        ? instance
                        : instance.Substring(0, i2);

                    sqlInstance.ComputerName = computerName;
                    sqlInstance.Instance = instance;
                    sqlInstance.ServiceName = serviceName;
                    sqlInstance.Spn = spn;

                    sqlInstance.AccountName = result["samaccountname"][0].ToString();
                    sqlInstance.AccountCn = result["cn"][0].ToString();

                    var sidBytes = (byte[])result["objectsid"][0];
                    sqlInstance.AccountSid = new SecurityIdentifier(sidBytes, 0).ToString();

                    var lastLogon = (long)result["lastlogon"][0];
                    sqlInstance.LastLogon = DateTime.FromBinary(lastLogon).ToString("G");
                    
                    instances.Add(sqlInstance);
                }
            }

            Console.WriteLine($"{instances.Count} found.");
            instances.ForEach(i => i.Print());
        }

        private sealed class SqlInstance
        {
            public string ComputerName { get; set; }
            public string Instance { get; set; }
            public string AccountSid { get; set; }
            public string AccountName { get; set; }
            public string AccountCn { get; set; }
            public string ServiceName { get; set; }
            public string Spn { get; set; }
            public string LastLogon { get; set; }

            public void Print()
            {
                Console.WriteLine("");
                Console.WriteLine("ComputerName:  {0}", ComputerName);
                Console.WriteLine("Instance:      {0}", Instance);
                Console.WriteLine("AccountSid:    {0}", AccountSid);
                Console.WriteLine("AccountName:   {0}", AccountName);
                Console.WriteLine("AccountCn:     {0}", AccountCn);
                Console.WriteLine("Service:       {0}", ServiceName);
                Console.WriteLine("SPN:           {0}", Spn);
                Console.WriteLine("LastLogon:     {0}", LastLogon);
            }
        }
    }
}