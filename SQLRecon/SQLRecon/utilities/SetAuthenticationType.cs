using System.Data.SqlClient;
using SQLRecon.Commands;

namespace SQLRecon.Utilities
{
    internal abstract class SetAuthenticationType
    {
        /// <summary>
        /// The EvaluateAuthenticationType method is responsible for creating
        /// a SQL connection object. This object is used by SQLRecon to manage
        /// the connection to a database. The connection object will be stored
        /// in the Var.Connect global variable for use throughout the program.
        /// </summary>
        /// <param name="authType">User supplied command line argument for authentication type.</param>
        internal static bool EvaluateAuthenticationType(string authType)
        {
            switch (authType)
            {
                case "wintoken":
                    return _winToken(authType);
                case "windomain":
                    return _winDomain(authType);
                case "local":
                    return _local(authType);
                case "entraid":
                    return _entraId(authType);
                case "azurelocal":
                    return _azureLocal(authType);
                default:
                    Print.Error("Set a valid authentication type.", true);
                    return false;
            }
        }

        /// <summary>
        /// The CreateSqlConnectionObject method creates a SQL connection object.
        /// This method can be particularly useful if you want to create multiple SQL connection objects.
        /// A single SQL connection object will only allow one instance of a 'SqlDataReader'.
        /// If you are writing a module where you need to execute multiple SQL queries against a database
        /// at the exact same time, then this module will facilitate that. Such as the Adsi module.
        /// </summary>
        /// <returns>A SQL connection object based on the current authentication type, or null if the authentication type is invalid.</returns>
        internal static SqlConnection CreateSqlConnectionObject()
        {
            SqlConnection connection;
            string serverInfo = $"{Var.SqlServer},{Var.Port}";
            switch (Var.AuthenticationType)
            {
                case "wintoken":
                    connection = SqlAuthentication.WindowsToken(serverInfo, Var.Database);
                    break;
                case "windomain":
                    connection = SqlAuthentication.WindowsDomain(serverInfo, Var.Database, Var.Domain, Var.Username, Var.Password);
                    break;
                case "local":
                    connection = SqlAuthentication.LocalAuthentication(serverInfo, Var.Database, Var.Username, Var.Password);
                    break;
                case "entraid":
                    connection = SqlAuthentication.EntraIdAuthentication(serverInfo, Var.Database, Var.Domain, Var.Username, Var.Password);
                    break;
                case "azurelocal":
                    connection = SqlAuthentication.AzureLocalAuthentication(serverInfo, Var.Database, Var.Username, Var.Password);
                    break;
                default:
                    Print.Error("Set a valid authentication type.", true);
                    return null;
            }
            
            return connection;
        }

        /// <summary>
        /// The _winToken method is called if the authentication type is WinToken.
        /// This requires a SQL server; otherwise, an error message is displayed.
        /// </summary>
        /// <param name="authType">Authentication type.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _winToken(string authType)
        {
            if (authType.ToLower().Equals("wintoken") && 
                !string.IsNullOrEmpty(Var.SqlServer))
            {
                // Create the SQL connection object
                Var.Connect = CreateSqlConnectionObject();
                return Var.Connect != null;
            }
            else
            {
                Print.Error("Must supply a SQL server (/h:, /host:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _winDomain method is called if the authentication type is WinDomain.
        /// This requires a SQL server, domain, username, and password;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="authType">Authentication type.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _winDomain(string authType)
        {
            if (authType.ToLower().Equals("windomain") && 
                !string.IsNullOrEmpty(Var.SqlServer) && 
                !string.IsNullOrEmpty(Var.Domain) && 
                !string.IsNullOrEmpty(Var.Username) && 
                !string.IsNullOrEmpty(Var.Password))
            {
                // Create the SQL connection object
                Var.Connect = CreateSqlConnectionObject();
                return Var.Connect != null;
            }
            else
            {
                Print.Error("Must supply a SQL server (/h:, /host:), domain (/d:, /domain:), username (/u:, /username:), " +
                             "and password (/p: /password:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _local method is called if the authentication type is Local.
        /// This requires a SQL server, username, and password;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="authType">Authentication type.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _local(string authType)
        {
            if (authType.ToLower().Equals("local") && 
                !string.IsNullOrEmpty(Var.SqlServer) && 
                !string.IsNullOrEmpty(Var.Username) && 
                !string.IsNullOrEmpty(Var.Password))
            {
                // Create the SQL connection object
                Var.Connect = CreateSqlConnectionObject();
                return Var.Connect != null;
            }
            else
            {
                Print.Error("Must supply a SQL server (/h:, /host:), username (/u:, /username:), and password (/p: /password:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _entraId method is called if the authentication type is EntraID.
        /// This requires a SQL server, domain, username, and password;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="authType">Authentication type.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _entraId(string authType)
        {
            if (authType.ToLower().Equals("entraid") &&  
                !string.IsNullOrEmpty(Var.SqlServer) &&
                !string.IsNullOrEmpty(Var.Domain) &&
                !string.IsNullOrEmpty(Var.Username) && 
                !string.IsNullOrEmpty(Var.Password))
            {
                if (!Var.Domain.Contains("."))
                {
                    Print.Error("Domain (/d:, /domain:) must be the fully qualified domain name (domain.com).", true);
                    // Go no further
                    return false;
                }
                else
                {
                    // Create the SQL connection object
                    Var.Connect = CreateSqlConnectionObject();
                    return Var.Connect != null;
                }
            }
            else
            {
                Print.Error("Must supply a SQL server (/h:, /host:), domain (/d:, /domain:), username (/u:, /username:), and password (/p: /password:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _azureLocal method is called if the authentication type is AzureLocal.
        /// This requires a SQL server, username, and password;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="authType">Authentication type.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _azureLocal(string authType)
        {
            if (authType.ToLower().Equals("azurelocal") && 
                !string.IsNullOrEmpty(Var.SqlServer) && 
                !string.IsNullOrEmpty(Var.Username) && 
                !string.IsNullOrEmpty(Var.Password))
            {
                // Create the SQL connection object
                Var.Connect = CreateSqlConnectionObject();
                return Var.Connect != null;
            }
            else
            {
                Print.Error("Must supply a SQL server (/h:, /host:), username (/u:, /username:), and password (/p: /password:).", true);
                // Go no further
                return false;
            }
        }
    }
}