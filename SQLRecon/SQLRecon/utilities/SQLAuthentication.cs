using System;
using System.Data.SqlClient;

namespace SQLRecon.Utilities
{
    internal class SqlAuthentication
    {
        private static readonly PrintUtils _print = new();
        private static string _connectionString;

        /// <summary>
        /// The WindowsToken method uses the processes current Windows token
        /// to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        public SqlConnection WindowsToken(string sqlServer, string database)
        {
            _connectionString = string.Format("Server={0}; Database={1}; Integrated Security=True;", sqlServer, database);
            return _authenticateToDatabase(_connectionString, System.Security.Principal.WindowsIdentity.GetCurrent().Name, sqlServer);
        }

        /// <summary>
        /// The WindowsDomain method uses cleartext AD domain credentials in conjunction with impersonation
        /// to create a Windows token, which is used to  authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <param name="domain"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        public SqlConnection WindowsDomain(string sqlServer, string database, string domain, string user, string password)
        {
            using (new Impersonation (domain, user, password))
            {
                _connectionString = string.Format("Server={0}; Database={1}; Integrated Security=True;", sqlServer, database);
                return _authenticateToDatabase(_connectionString, string.Format("{0}\\{1}", domain, user), sqlServer);
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
        public SqlConnection LocalAuthentication(string sqlServer, string database, string user, string password)
        {
            _connectionString = string.Format("Server={0}; Database={1}; Integrated Security=False; User Id={2}; Password={3};", sqlServer, database, user, password);
            return _authenticateToDatabase(_connectionString, user, sqlServer);
        }

        /// <summary>
        /// The AzureADAuthentication method uses cleartext Azure AD domain credentials 
        /// to authenticate to a supplied database.
        /// </summary>
        /// <param name="sqlServer"></param>
        /// <param name="database"></param>
        /// <param name="domain"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>A valid SQL connection object that is used to authenticate against databases.</returns>
        public SqlConnection AzureADAuthentication(string sqlServer, string database, string domain, string user, string password)
        {
            user = string.Format("{0}@{1}", user, domain);

            _connectionString = string.Format("Server={0}; Database={1}; Authentication=Active Directory Password; " +
                "Encrypt=True; TrustServerCertificate=False; User ID={2}; Password={3};", sqlServer, database, user, password);
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
        public SqlConnection AzureLocalAuthentication(string sqlServer, string database, string user, string password)
        {
            _connectionString = string.Format("Server={0}; Database={1}; " +
                "TrustServerCertificate=False; Encrypt=True; User Id={2}; Password={3};", sqlServer, database, user, password);
            return _authenticateToDatabase(_connectionString, user, sqlServer);
        }

        /// <summary>
        /// The _authenticateTodatabase method is responsible for creating a SQL connection object
        /// to a supplied database.
        /// </summary>
        /// <param name="conString"></param>
        /// <param name="user"></param>
        /// <param name="sqlServer"></param>
        /// <returns>
        /// If the connection to the database succeeds, a SQL connection object is returned, otherwise
        /// an eror message is provided and the program is gracefully exited.
        /// </returns>
        private SqlConnection _authenticateToDatabase(string conString, string user, string sqlServer)
        {
            SqlConnection connection = new SqlConnection(conString);

            try
            {
                connection.Open();
                return connection;
            }

            catch (Exception ex)
            {
                if (ex.ToString().ToLower().Contains("login failed"))
                {
                    _print.Error(string.Format("Invalid credentials supplied for {0}.", user), true);
                }
                else if (ex.ToString().ToLower().Contains("network-related"))
                {
                    _print.Error(string.Format("{0} can not be reached.", sqlServer.Replace(",", ":")), true);
                }
                else if (ex.ToString().ToLower().Contains("adalsql.dll"))
                {
                    _print.Error("Unable to load adal.sql or adalsql.dll.", true);
                }
                else 
                {
                    _print.Error(string.Format("{0} can not log in to {1}.", user, sqlServer.Replace(",", ":")), true);
                    Console.WriteLine(ex);
                }

                connection.Close();
                // Go no further.
                return null;
            }
        }
    }
}
