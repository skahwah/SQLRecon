using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Info
    {
        /// <summary>
        /// The StandardOrImpersonation method will connect to a SQL server
        /// and obtain information about the local SQL server instance.
        /// </summary>
        internal static void StandardOrImpersonation(string impersonate = null)
        {
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "ComputerName", Query.GetComputerName },
                { "DomainName", Query.GetDomainName },
                { "ServicePid", Query.GetServicePid },
                { "OsMachineType", Query.GetOsMachineType },
                { "OsVersion", Query.GetOsVersion },
                { "SqlServerServiceName", Query.GetSqlServerServiceName },
                { "SqlServiceAccountName", Query.GetSqlServiceAccountName },
                { "AuthenticationMode", Query.GetAuthenticationMode },
                { "ForcedEncryption", Query.GetForcedEncryption },
                { "Clustered", Query.GetClustered },
                { "SqlVersionNumber", Query.GetSqlVersionNumber },
                { "SqlMajorVersionNumber", Query.GetSqlMajorVersionNumber },
                { "SqlServerEdition", Query.GetSqlServerEdition },
                { "SqlServerServicePack", Query.GetSqlServerServicePack },
                { "OsArchitecture", Query.GetOsArchitecture },
                { "OsVersionNumber", Query.GetOsVersionNumber },
                { "CurrentLogon", Query.GetCurrentLogon },
                { "ActiveSessions", Query.GetActiveSessions }
            };

            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }
            
            // Check to see if the user is a sysadmin. Consider impersonation.
            bool sysadmin = (string.IsNullOrEmpty(impersonate))
                ? Roles.CheckRoleMembership(Var.Connect, "sysadmin")
                : Roles.CheckRoleMembership(Var.Connect, "sysadmin", Var.Impersonate);
            
            // Remove certain queries from the dictionary if the user is not a sysadmin
            if (sysadmin == false)
            {
                queries.Remove("OsMachineType");
                queries.Remove("OsVersion");
            }
     
            Dictionary<string, string> results = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> entry in queries)
            { 
                results.Add(entry.Key, Sql.Query(Var.Connect, queries[entry.Key]));
            }
            
            Console.WriteLine();
            Console.WriteLine(Print.ConvertDictionaryToMarkdownTable(results, "Object", "Value"));
        }
        
        /// <summary>
        /// The LinkedOrChain method will connect to a linked SQL server
        /// and obtain information about the local SQL server instance.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        internal static void LinkedOrChain(string linkedSqlServer, string[] linkedSqlServerChain = null)
        {
            // The queries dictionary contains all queries used by this module
            // The dictionary key name for RPC formatted queries must start with RPC
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "ComputerName", Query.GetComputerName },
                { "DomainName", Query.GetDomainName },
                { "ServicePid", Query.GetServicePid },
                { "rpc_OsMachineType", Query.GetOsMachineType },
                { "rpc_OsVersion", Query.GetOsVersion },
                { "SqlServerServiceName", Query.GetSqlServerServiceName },
                { "rpc_SqlServiceAccountName", Query.GetSqlServiceAccountName },
                { "rpc_AuthenticationMode", Query.GetAuthenticationMode },
                { "rpc_ForcedEncryption", Query.GetForcedEncryption },
                { "Clustered", Query.GetClustered },
                { "SqlVersionNumber", Query.GetSqlVersionNumber },
                { "SqlMajorVersionNumber", Query.GetSqlMajorVersionNumber },
                { "SqlServerEdition", Query.GetSqlServerEdition },
                { "SqlServerServicePack", Query.GetSqlServerServicePack },
                { "OsArchitecture", Query.GetOsArchitecture },
                { "OsVersionNumber", Query.GetOsVersionNumber },
                { "CurrentLogon", Query.GetCurrentLogon },
                { "ActiveSessions", Query.GetActiveSessions }
            };
            
            // Check to see if the user is a sysadmin. Consider linked SQL srver chains.
            bool sysadmin = (linkedSqlServerChain == null)
                ? Roles.CheckLinkedRoleMembership(Var.Connect, "sysadmin", linkedSqlServer)
                : Roles.CheckLinkedRoleMembership(Var.Connect, "sysadmin", null, linkedSqlServerChain);
            
            // Remove certain queries from the dictionary if the user is not a sysadmin
            if (sysadmin == false)
            {
                queries.Remove("rpc_OsMachineType");
                queries.Remove("rpc_OsVersion");
                queries.Remove("rpc_SqlServiceAccountName");
                queries.Remove("rpc_AuthenticationMode");
                queries.Remove("rpc_ForcedEncryption");
            }
     
            Dictionary<string, string> results = new Dictionary<string, string>();
            
            queries = (linkedSqlServerChain == null)
                // Format all queries so that they are compatible for execution on a linked SQL server.
                ? Format.LinkedDictionary(Var.LinkedSqlServer, queries)
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                : Format.LinkedChainDictionary(Var.LinkedSqlServersChain, queries);
            
            foreach (KeyValuePair<string, string> entry in queries)
            { 
                results.Add(entry.Key, Sql.Query(Var.Connect, queries[entry.Key]));
            }
                
            Console.WriteLine();
            Console.WriteLine(Print.ConvertDictionaryToMarkdownTable(results, "Object", "Value"));
        }
        
        /// <summary>
        /// The GetInfoViaUdpRequest method will send a UDP request to
        /// port 1434 on the remote SQL server along with the magic byte value
        /// of 0x02 to receive information about the SQL instance.
        /// A timeout and port value is optional.
        /// DNS resolution is supported.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="port"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        internal static string GetInfoViaUdpRequest(string sqlServer, int port, int timeout)
        {
            UdpClient udpClient = new UdpClient();

            // Check to see if a DNS name, or IP address was provided
            bool validateIp = IPAddress.TryParse(sqlServer, out IPAddress ip);
            
            // If an DNS name was provided, attempt to resolve to IP
            if (validateIp == false)
            {
                try
                {
                    IPHostEntry hostEntry = Dns.GetHostEntry(sqlServer);
                    
                    // There are cases when DNS can return multiple IP addresses, select the first one
                    if (hostEntry.AddressList.Length > 0)
                    {
                        ip = hostEntry.AddressList[0];
                    }
                }
                catch (Exception)
                {
                    return Print.Error($"Unable to resolve DNS name for {sqlServer}");
                }
            }
            
            // Ensure that the timeout value is set to milliseconds. Default is 4 seconds.
            timeout *= 1000;
            udpClient.Client.SendTimeout = timeout;
            udpClient.Client.ReceiveTimeout = timeout;

            // Create a new client request
            // Default port is UDP 1434
            IPEndPoint request = new IPEndPoint(ip, port); 
            
            try
            {
                udpClient.Connect(request);
                
                // Send the magic 0x02 byte
                udpClient.Send(new byte[] { 2 }, 1);
                
                byte[] receivedData = udpClient.Receive(ref request);
                
                // Covert the data received from byte to string
                string data = System.Text.Encoding.UTF8.GetString(receivedData);
                
                Dictionary<string, string> sqlServerInfo = new Dictionary<string, string>();
            
                // Parse the results into a dictionary
                if (!string.IsNullOrEmpty(data))
                {
                    // The received string will be similar to
                    // ServerName;SQL01;InstanceName;SQLEXPRESS;IsClustered;No;Version;16.0.1000.6;tcp;1433;;receive data from 172.16.10.101:1434
                    List<string> result = data.Split(';').ToList();

                    for (int i = 0; i < result.Count; i++)
                    {
                        Dictionary<string, string> dataFields =  new Dictionary<string, string>()
                        {
                            { "servername", "Server Name"},
                            { "instancename", "Instance Name"},
                            { "isclustered", "Is Clustered?"},
                            { "version", "Version"},
                            { "tcp", "TCP Port"},
                        
                        };

                        foreach (KeyValuePair<string, string> entry in dataFields)
                        {
                            if (result[i].ToLower().Contains(entry.Key))
                            {
                                sqlServerInfo.Add(entry.Value, result[i + 1]);
                            }
                        }
                    }
                }
                
                if (sqlServerInfo.Count > 0)
                {
                    return Print.ConvertDictionaryToMarkdownTable(sqlServerInfo, "Object", "Value");
                }
                else
                {
                    return Print.Error($"Unable to connect to UDP port {port.ToString()} on {sqlServer}");
                }
                
            }
            catch (Exception) 
            {
                return Print.Error($"Unable to connect to UDP port {port.ToString()} on {sqlServer}");
            }
        }
    }
}