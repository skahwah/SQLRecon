using System;
using System.Data.SqlClient;
using SQLRecon.Commands;

namespace SQLRecon.Utilities
{
    internal abstract class SqlAuthentication
    {
        private static string _connectionString;
        
        /// <summary>
        /// The WindowsToken method uses Windows token in the current process
        /// to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        internal static SqlConnection WindowsToken(string sqlServer, string database)
        {
            _connectionString = $"Server={sqlServer}; Database={database}; Integrated Security=True;";
            
            return _authenticateToDatabase(_connectionString, System.Security.Principal.WindowsIdentity.GetCurrent().Name, sqlServer);
        }

        /// <summary>
        /// The WindowsDomain method uses cleartext AD domain credentials in conjunction with impersonation
        /// to create a Windows token, which is used to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <param name="domain"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        internal static SqlConnection WindowsDomain(string sqlServer, string database, string domain, string user, string password)
        {
            using (new Impersonate (domain, user, password))
            {
                _connectionString = $"Server={sqlServer}; Database={database}; Integrated Security=True;";
                
                return _authenticateToDatabase(_connectionString, $"{domain}\\{user}", sqlServer);
            }
        }

        /// <summary>
        /// The LocalAuthentication method uses cleartext local SQL database credentials
        /// to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        internal static SqlConnection LocalAuthentication(string sqlServer, string database, string user, string password)
        {
            _connectionString = $"Server={sqlServer}; Database={database}; Integrated Security=False; User Id={user}; Password={password};";
            
            return _authenticateToDatabase(_connectionString, user, sqlServer);
        }

        /// <summary>
        /// The EntraIdAuthentication method uses cleartext Entra ID domain credentials
        /// to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <param name="domain"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        internal static SqlConnection EntraIdAuthentication(string sqlServer, string database, string domain, string user, string password)
        {
            user = $"{user}@{domain}";

            _connectionString = $"Server={sqlServer}; Database={database}; Authentication=Active Directory Password; " +
                                $"Encrypt=True; TrustServerCertificate=False; User ID={user}; Password={password};";
            
            return _authenticateToDatabase(_connectionString, user, sqlServer);
        }

        /// <summary>
        /// The AzureLocationAuthentication method uses cleartext Azure local database credentials
        /// to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        internal static SqlConnection AzureLocalAuthentication(string sqlServer, string database, string user, string password)
        {
            _connectionString = $"Server={sqlServer}; Database={database}; TrustServerCertificate=False; Encrypt=True; User Id={user}; Password={password};";
            
            return _authenticateToDatabase(_connectionString, user, sqlServer);
        }

        /// <summary>
        /// The _authenticateToDatabase method is responsible for creating a SQL connection object
        /// to a supplied database.
        /// </summary>
        /// <param name="conString"></param>
        /// <param name="user"></param>
        /// <param name="sqlServer"></param>
        /// <returns>
        /// If the connection to the database succeeds, a SQL connection object is returned, otherwise
        /// an error message is provided and the program gracefully exits.
        /// </returns>
        private static SqlConnection _authenticateToDatabase(string conString, string user, string sqlServer)
        {
            // Set timeout to 4s, unless specified using the "/timeout" or "/t" flags.
            _connectionString = $"{conString} Connect Timeout={Var.Timeout};";
            
            // Create SQL connection object
            SqlConnection connection = new SqlConnection(_connectionString);

            try
            {
                connection.Open();
                if (Var.Debug || Var.Verbose)
                {
                    Print.Debug($"Connecting to '{Var.Database}' on {Var.SqlServer}:{Var.Port} using {Var.AuthenticationType}.");
                    Print.Nested($"Connection String: {_connectionString}", true);
                    Print.Nested($"Data Source: {connection.DataSource}", true);
                    Print.Nested($"Database: {connection.Database}", true);
                    Print.Nested($"Server Version: {connection.ServerVersion}", true);
                    Print.Nested($"State: {connection.State}", true);
                    Print.Nested($"Workstation ID: {connection.WorkstationId}", true);
                    Print.Nested($"Packet Size: {connection.PacketSize}", true);
                    Print.Nested($"Client Connection ID: {connection.ClientConnectionId}", true);
                    Print.Nested($"Application Name: {connection.WorkstationId}", true);
                }

                return connection;
            }
            catch (Exception ex)
            {
                if (ex.ToString().ToLower().Contains("login failed"))
                {
                    Print.Error($"'{user}' can not connect to '{Var.Database}' on {sqlServer.Replace(",",":")}", true);
                    connection.Close();
                    return null;
                }
                else if (ex.ToString().ToLower().Contains("network-related"))
                {
                    Print.Error($"{sqlServer.Replace(",", ":")} can not be reached.", true);
                    connection.Close();
                    return null;
                }
                else if (ex.ToString().ToLower().Contains("adalsql.dll"))
                {
                    Print.Error("Unable to load adal.sql or adalsql.dll.", true);
                    connection.Close();
                    return null;
                }
                else
                {
                    Print.Error($"{user} can not log in to {sqlServer.Replace(",", ":")}.", true);
                    connection.Close();
                    return null;
                }
            }
        }
    }
}
