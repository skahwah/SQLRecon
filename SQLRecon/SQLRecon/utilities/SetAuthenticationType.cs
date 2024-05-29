using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using SQLRecon.Commands;

namespace SQLRecon.Utilities
{
    internal class SetAuthenticationType
    {
        private static readonly GlobalVariables _gV = new();
        private static readonly PrintUtils _print = new();
        private static readonly SqlAuthentication _sqlAuthentication = new();


        /// <summary>
        /// The EvaluateAuthenticationType method is responsible for creating
        /// a SQL connection object. This object is used by SQLRecon to manage
        /// the connection to a database. The connection object will be stored
        /// in the _gV.Connect global variable for use throughout the program.
        /// </summary>
        /// <param name="argumentDictionary">User supplied command line arguments.</param>
        public static bool EvaluateAuthenticationType(Dictionary<string, string> argumentDictionary)
        {
            // Set the default authentication type to "wintoken" if not provided
            string auth = argumentDictionary.ContainsKey("auth") ? argumentDictionary["auth"].ToLower() : "wintoken";
            string host = argumentDictionary.ContainsKey("host") ? argumentDictionary["host"] : null;
            string module = argumentDictionary.ContainsKey("module") ? argumentDictionary["module"] : null;
            string database = argumentDictionary.ContainsKey("database") ? argumentDictionary["database"] : null;
            string port = argumentDictionary.ContainsKey("port") ? argumentDictionary["port"] : "1433";
            string domain = argumentDictionary.ContainsKey("domain") ? argumentDictionary["domain"] : null;
            string username = argumentDictionary.ContainsKey("username") ? argumentDictionary["username"] : null;
            string password = argumentDictionary.ContainsKey("password") ? argumentDictionary["password"] : null;

            return auth switch
            {
                "wintoken" => _winToken(auth, host, module, database, port),
                "windomain" => _winDomain(auth, host, module, domain, username, password, database, port),
                "local" => _local(auth, host, module, username, password, database, port),
                "azuread" => _azureAd(auth, host, module, domain, username, password, database, port),
                "azurelocal" => _azureLocal(auth, host, module, username, password, database, port),
                _ => false,
            };
        }

        /// <summary>
        /// The CreateSqlConnectionObject method creates a SQL connection object.
        /// This method can be particularly useful if you want to create multiple SQL connection objects.
        /// A single SQL connection object will only allow one instance of a 'SqlDataReader'.
        /// If you are writing a module where you need to execute multiple SQL queries against a database
        /// at the exact same time, then this module will facilitate that.
        /// </summary>
        /// <returns>A SQL connection object based on the current authentication type, or null if the authentication type is invalid.</returns>
        public static SqlConnection CreateSqlConnectionObject()
        {
            try
            {
                SqlConnection connection = null;
                string serverInfo = $"{_gV.SqlServer},{_gV.Port}";
                string authType = _gV.AuthenticationType.ToLower();

                _print.Status($"Connecting to MS SQL instance using {_gV.AuthenticationType} on {_gV.SqlServer}:{_gV.Port} for {_gV.Database}.", true);

                switch (authType)
                {
                    case "wintoken":
                        connection = _sqlAuthentication.WindowsToken(serverInfo, _gV.Database);
                        break;
                    case "windomain":
                        connection = _sqlAuthentication.WindowsDomain(serverInfo, _gV.Database, _gV.Domain, _gV.Username, _gV.Password);
                        break;
                    case "local":
                        connection = _sqlAuthentication.LocalAuthentication(serverInfo, _gV.Database, _gV.Username, _gV.Password);
                        break;
                    case "azuread":
                        connection = _sqlAuthentication.AzureADAuthentication(serverInfo, _gV.Database, _gV.Domain, _gV.Username, _gV.Password);
                        break;
                    case "azurelocal":
                        connection = _sqlAuthentication.AzureLocalAuthentication(serverInfo, _gV.Database, _gV.Username, _gV.Password);
                        break;
                    default:
                        _print.Warning("Invalid authentication type specified.", true);
                        return null;
                }
                return connection;
            }
            catch (Exception ex)
            {
                _print.Error($"An error occurred while creating the SQL connection object: {ex.Message}", true);
                return null;
            }
        }

        /// <summary>
        /// The _winToken method is called if the authentication type is WinToken.
        /// This requires a SQL server and module; otherwise, an error message is displayed.
        /// </summary>
        /// <param name="auth">Authentication type.</param>
        /// <param name="host">SQL server host. If not provided, the current machine name is used.</param>
        /// <param name="module">Module name. This is required.</param>
        /// <param name="database">Optional database name.</param>
        /// <param name="port">Optional port number, defaults to 1433 if not provided.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _winToken(string auth, string host, string module, string database = null, string port = "1433")
        {
            if (auth.ToLower().Equals("wintoken") && !string.IsNullOrEmpty(module))
            {
                _gV.AuthenticationType = auth.ToLower();
                _gV.SqlServer = !string.IsNullOrEmpty(host) ? host : System.Environment.MachineName;

                // Optional argument for database
                if (!string.IsNullOrEmpty(database))
                {
                    _gV.Database = database.ToLower();
                }

                // Set port, defaulting to 1433 if not provided
                _gV.Port = port;

                // Create the SQL connection object
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply a module (/m:, /module:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _winDomain method is called if the authentication type is WinDomain.
        /// This requires a SQL server, domain, username, password, and module;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="auth">Authentication type.</param>
        /// <param name="host">SQL server host. If not provided, the current machine name is used.</param>
        /// <param name="module">Module name. This is required.</param>
        /// <param name="domain">Domain name. This is required.</param>
        /// <param name="username">Username. This is required.</param>
        /// <param name="password">Password. This is required.</param>
        /// <param name="database">Optional database name.</param>
        /// <param name="port">Optional port number, defaults to 1433 if not provided.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _winDomain(string auth, string host, string module, string domain, string username, string password, string database = null, string port = "1433")
        {
            if (auth.ToLower().Equals("windomain") && !string.IsNullOrEmpty(module) && !string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                _gV.AuthenticationType = auth.ToLower();
                _gV.SqlServer = !string.IsNullOrEmpty(host) ? host : System.Environment.MachineName;
                _gV.Domain = domain;
                _gV.Username = username;
                _gV.Password = password;

                // Optional argument for database
                if (!string.IsNullOrEmpty(database))
                {
                    _gV.Database = database.ToLower();
                }

                // Set port, defaulting to 1433 if not provided
                _gV.Port = port;

                // Create the SQL connection object
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply a domain (/d:, /domain:), username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _local method is called if the authentication type is Local.
        /// This requires a SQL server, username, password, and module;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="auth">Authentication type.</param>
        /// <param name="host">SQL server host. If not provided, the current machine name is used.</param>
        /// <param name="module">Module name. This is required.</param>
        /// <param name="username">Username. This is required.</param>
        /// <param name="password">Password. This is required.</param>
        /// <param name="database">Optional database name.</param>
        /// <param name="port">Optional port number, defaults to 1433 if not provided.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _local(string auth, string host, string module, string username, string password, string database = null, string port = "1433")
        {
            if (auth.ToLower().Equals("local") && !string.IsNullOrEmpty(module) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                _gV.AuthenticationType = auth.ToLower();
                _gV.SqlServer = !string.IsNullOrEmpty(host) ? host : System.Environment.MachineName;
                _gV.Username = username;
                _gV.Password = password;

                // Optional argument for database
                if (!string.IsNullOrEmpty(database))
                {
                    _gV.Database = database.ToLower();
                }

                // Set port, defaulting to 1433 if not provided
                _gV.Port = port;

                // Create the SQL connection object
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply an username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _azureAd method is called if the authentication type is AzureAD.
        /// This requires a SQL server, domain, username, password, and module;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="auth">Authentication type.</param>
        /// <param name="host">SQL server host. If not provided, the current machine name is used.</param>
        /// <param name="module">Module name. This is required.</param>
        /// <param name="domain">Domain name. This is required.</param>
        /// <param name="username">Username. This is required.</param>
        /// <param name="password">Password. This is required.</param>
        /// <param name="database">Optional database name.</param>
        /// <param name="port">Optional port number, defaults to 1433 if not provided.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _azureAd(string auth, string host, string module, string domain, string username, string password, string database = null, string port = "1433")
        {
            if (auth.ToLower().Equals("azuread") && !string.IsNullOrEmpty(module) && !string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                if (!domain.Contains("."))
                {
                    _print.Error("Domain (/d:, /domain:) must be the fully qualified domain name (domain.com).", true);
                    // Go no further
                    return false;
                }
                else
                {
                    _gV.AuthenticationType = auth.ToLower();
                    _gV.SqlServer = !string.IsNullOrEmpty(host) ? host : System.Environment.MachineName;
                    _gV.Domain = domain;
                    _gV.Username = username;
                    _gV.Password = password;

                    // Optional argument for database
                    if (!string.IsNullOrEmpty(database))
                    {
                        _gV.Database = database.ToLower();
                    }

                    // Set port, defaulting to 1433 if not provided
                    _gV.Port = port;

                    // Create the SQL connection object
                    _gV.Connect = CreateSqlConnectionObject();
                    return true;
                }
            }
            else
            {
                _print.Error("Must supply a domain (/d:, /domain:), username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _azureLocal method is called if the authentication type is AzureLocal.
        /// This requires a SQL server, username, password, and module;
        /// otherwise, an error message is displayed.
        /// </summary>
        /// <param name="auth">Authentication type.</param>
        /// <param name="host">SQL server host. If not provided, the current machine name is used.</param>
        /// <param name="module">Module name. This is required.</param>
        /// <param name="username">Username. This is required.</param>
        /// <param name="password">Password. This is required.</param>
        /// <param name="database">Optional database name.</param>
        /// <param name="port">Optional port number, defaults to 1433 if not provided.</param>
        /// <returns>True if the connection is successfully created, false otherwise.</returns>
        private static bool _azureLocal(string auth, string host, string module, string username, string password, string database = null, string port = "1433")
        {
            if (auth.ToLower().Equals("azurelocal") && !string.IsNullOrEmpty(module) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                _gV.AuthenticationType = auth.ToLower();
                _gV.SqlServer = !string.IsNullOrEmpty(host) ? host : System.Environment.MachineName;
                _gV.Username = username;
                _gV.Password = password;

                // Optional argument for database
                if (!string.IsNullOrEmpty(database))
                {
                    _gV.Database = database.ToLower();
                }

                // Set port, defaulting to 1433 if not provided
                _gV.Port = port;

                // Create the SQL connection object
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply a username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further
                return false;
            }
        }
    }
}
