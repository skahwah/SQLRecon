using System;
using System.Collections.Generic;
using System.Security.Principal;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal static class DomainSPNs
    {
        private static readonly PrintUtils _print = new();

        /// <summary>
        /// The GetMSSQLSPNs method will obtain any SQL servers from
        /// Active Directory if the SQL server has an associated SPN.
        /// </summary>
        /// <param name="domain"></param>
        public static void GetMSSQLSPNs(string domain = null)
        {
            _print.Status("Looking for MSSQL SPNs ...", true);

            var searcher = string.IsNullOrWhiteSpace(domain)
                ? new DomainSearcher()
                : new DomainSearcher($"LDAP://{domain}");

            var ldap = new Ldap(searcher);

            const string ldapFilter = "(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))";
            var properties = new[] { "cn", "samaccountname", "objectsid", "serviceprincipalname", "lastlogon" };

            var results = ldap.ExecuteQuery(ldapFilter, properties);
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

            _print.Status(string.Format("{0} found.", instances.Count), true);
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
                _print.Nested(string.Format("ComputerName:  {0}", ComputerName), true);
                _print.Nested(string.Format("Instance:      {0}", Instance), true);
                _print.Nested(string.Format("AccountSid:    {0}", AccountSid), true);
                _print.Nested(string.Format("AccountName:   {0}", AccountName), true);
                _print.Nested(string.Format("AccountCn:     {0}", AccountCn), true);
                _print.Nested(string.Format("Service:       {0}", ServiceName), true);
                _print.Nested(string.Format("SPN:           {0}", Spn), true);
                _print.Nested(string.Format("LastLogon:     {0}", LastLogon), true);
            }
        }
    }
}