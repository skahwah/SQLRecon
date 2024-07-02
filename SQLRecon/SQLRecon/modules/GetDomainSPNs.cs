using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Net;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal static class DomainSpns
    {
        /// <summary>
        /// The GetSqlSpns method will obtain any SQL servers from
        /// Active Directory if the SQL server has an associated SPN.
        /// </summary>
        /// <param name="domain"></param>
        internal static void GetSqlSpns(string domain = null)
        {
            Print.Status("Looking for MSSQL SPNs ...", true);

            DomainSearcher searcher = string.IsNullOrWhiteSpace(domain)
                ? new DomainSearcher()
                : new DomainSearcher($"LDAP://{domain}");

            Ldap ldap = new Ldap(searcher);

            const string ldapFilter = "(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))";
            string[] properties = new[] { "cn", "samaccountname", "objectsid", "serviceprincipalname", "lastlogon" };

            Dictionary<string, Dictionary<string, object[]>> results = ldap.ExecuteLdapQuery(ldapFilter, properties);
            List<SqlInstance> instances = new List<SqlInstance>();

            foreach (Dictionary<string, object[]> result in results.Values)
            {
                foreach (string spn in result["serviceprincipalname"])
                {
                    SqlInstance sqlInstance = new SqlInstance();

                    // parse the SPN string
                    // MSSQLSvc/sql-1.testlab.local:1433
                    // MSSQLSvc/sql-1.testlab.local

                    int i1 = spn.IndexOf('/');

                    string serviceName = spn.Substring(0, i1);
                    string instance = spn.Substring(i1 + 1, spn.Length - i1 - 1);

                    int i2 = instance.IndexOf(':');

                    string computerName = i2 == -1
                        ? instance
                        : instance.Substring(0, i2);

                    sqlInstance.ComputerName = computerName;
                    IPAddress[] addresses = Dns.GetHostAddresses(computerName);
                    sqlInstance.IpAddress = addresses.Length > 0 ? addresses[0].ToString() : "No IP found";
                    sqlInstance.Instance = instance;
                    sqlInstance.ServiceName = serviceName;
                    sqlInstance.Spn = spn;

                    sqlInstance.AccountName = result["samaccountname"][0].ToString();
                    sqlInstance.AccountCn = result["cn"][0].ToString();

                    byte[] sidBytes = (byte[])result["objectsid"][0];
                    sqlInstance.AccountSid = new SecurityIdentifier(sidBytes, 0).ToString();

                    long lastLogon = (long)result["lastlogon"][0];
                    sqlInstance.LastLogon = DateTime.FromBinary(lastLogon).ToString("G");

                    instances.Add(sqlInstance);
                }
            }

            Print.Status($"{instances.Count} found.", true);
            
            instances.ForEach(i => i.PrintInfo());
        }
        private sealed class SqlInstance
        {
            internal string ComputerName { get; set; }
            internal string IpAddress { get; set; }
            internal string Instance { get; set; }
            internal string AccountSid { get; set; }
            internal string AccountName { get; set; }
            internal string AccountCn { get; set; }
            internal string ServiceName { get; set; }
            internal string Spn { get; set; }
            internal string LastLogon { get; set; }

            internal void PrintInfo()
            {
                Console.WriteLine();
                
                Dictionary<string, string> spnInfo  = new Dictionary<string, string>
                {
                    { "Computer Name", ComputerName },
                    { "IP Address", IpAddress },
                    { "Instance", Instance },
                    { "Account SID", AccountSid },
                    { "Account Name", AccountName },
                    { "Account CN", AccountCn },
                    { "Service", ServiceName },
                    { "SPN", Spn },
                    { "Last Logon", LastLogon }
                };

                Console.WriteLine(Print.ConvertDictionaryToMarkdownTable(spnInfo, "SPN Objects", "Value"));
            }
        }
    }
}