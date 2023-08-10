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
            if (argumentDictionary["auth"].ToLower().Equals("wintoken"))
            {
                return _winToken(argumentDictionary);
            }
            else if (argumentDictionary["auth"].ToLower().Equals("windomain"))
            {
                return _winDomain(argumentDictionary);
            }
            else if (argumentDictionary["auth"].ToLower().Equals("local"))
            {
                return _local(argumentDictionary);
            }
            else if (argumentDictionary["auth"].ToLower().Equals("azuread"))
            {
                return _azureAd(argumentDictionary);
            }
            else if (argumentDictionary["auth"].ToLower().Equals("azurelocal"))
            {
                return _azureLocal(argumentDictionary);
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// The CreateSqlConnectionObject method creates a SQL connection object.
        /// This method can be particularily useful if you want to create multiple SQL connection objects.
        /// A single SQL connection object will only allow once instance of a 'SqlDataReader'.
        /// If you are writing a module where you need to execute multiple SQL queries against a database
        /// at the exact same time, then this module will facilitate that.
        /// </summary>
        /// <returns></returns>
        public static SqlConnection CreateSqlConnectionObject()
        {
            if (_gV.AuthenticationType.Equals("wintoken"))
            {
                return _sqlAuthentication.WindowsToken(_gV.SqlServer + "," + _gV.Port, _gV.Database);
            }
            else if (_gV.AuthenticationType.Equals("windomain"))
            {
                return _sqlAuthentication.WindowsDomain(_gV.SqlServer + "," + _gV.Port,
                    _gV.Database,
                    _gV.Domain,
                    _gV.Username,
                    _gV.Password);
            }
            else if (_gV.AuthenticationType.Equals("local"))
            {
                return _sqlAuthentication.LocalAuthentication(_gV.SqlServer + "," + _gV.Port,
                        _gV.Database,
                        _gV.Username,
                        _gV.Password);
            }
            else if (_gV.AuthenticationType.Equals("azuread"))
            {
                return _sqlAuthentication.AzureADAuthentication(_gV.SqlServer + "," + _gV.Port,
                        _gV.Database,
                        _gV.Domain,
                        _gV.Username,
                        _gV.Password);
            }
            else if (_gV.AuthenticationType.Equals("azurelocal"))
            {
                return _sqlAuthentication.AzureLocalAuthentication(_gV.SqlServer + "," + _gV.Port,
                        _gV.Database,
                        _gV.Username,
                        _gV.Password);
            }
            else
            {
                // This case should never get hit, but if it does, return nothing.
                return null;
            }
        }


        /// <summary>
        /// The _winToken method is called if the authentication type is WinToken.
        /// This requires a SQL server and module otherwise an error message is displayed.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static bool _winToken(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary["auth"].ToLower().Equals("wintoken") &&
                argumentDictionary.ContainsKey("host") && argumentDictionary.ContainsKey("module"))
            {
                _gV.AuthenticationType = argumentDictionary["auth"].ToLower();
                _gV.SqlServer = argumentDictionary["host"];

                // Optional argument for database
                if (argumentDictionary.ContainsKey("database"))
                {
                    _gV.Database = argumentDictionary["database"].ToLower();
                }

                // Optional argument for port, defaults to 1433
                if (argumentDictionary.ContainsKey("port"))
                {
                    _gV.Port = argumentDictionary["port"];
                }

                // Create the SQL connection object
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply a SQL server (/h:, /host:) and module (/m:, /module:).", true);
                // Go no further
                return false;
            }
        }

        /// <summary>
        /// The _winDomain method is called if the authentication type is WinDomain.
        /// This requires a SQL server, domain, username, password and module
        /// otherwise an error message is displayed.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static bool _winDomain(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary["auth"].ToLower().Equals("windomain") && argumentDictionary.ContainsKey("host") &&
                argumentDictionary.ContainsKey("domain") && argumentDictionary.ContainsKey("username") &&
                argumentDictionary.ContainsKey("password") && argumentDictionary.ContainsKey("module"))
            {
                _gV.AuthenticationType = argumentDictionary["auth"].ToLower();
                _gV.SqlServer = argumentDictionary["host"];
                _gV.Domain = argumentDictionary["domain"];
                _gV.Username = argumentDictionary["username"];
                _gV.Password = argumentDictionary["password"];

                // Optional arg for database.
                if (argumentDictionary.ContainsKey("database"))
                {
                    _gV.Database = argumentDictionary["database"].ToLower();
                }

                // Optional argument for port, defaults to 1433
                if (argumentDictionary.ContainsKey("port"))
                {
                    _gV.Port = argumentDictionary["port"];
                }

                // Create the SQL connection object.
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply a SQL server (/h:, /host:), domain (/d:, /domain:), username (/u:, /username:), " +
                    "password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further.
                return false;
            }
        }

        /// <summary>
        /// The _local method is called if the authentication type is Local.
        /// This requires a SQL server, username, password, and module
        /// otherwise an error message is displayed.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static bool _local(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary["auth"].ToLower().Equals("local") && argumentDictionary.ContainsKey("host") &&
                argumentDictionary.ContainsKey("username") && argumentDictionary.ContainsKey("password") &&
                argumentDictionary.ContainsKey("module"))
            {
                _gV.AuthenticationType = argumentDictionary["auth"].ToLower();
                _gV.SqlServer = argumentDictionary["host"];
                _gV.Username = argumentDictionary["username"];
                _gV.Password = argumentDictionary["password"];

                // Optional arg for database.
                if (argumentDictionary.ContainsKey("database"))
                {
                    _gV.Database = argumentDictionary["database"].ToLower();
                }

                // Optional argument for port, defaults to 1433.
                if (argumentDictionary.ContainsKey("port"))
                {
                    _gV.Port = argumentDictionary["port"];
                }

                // Create the SQL connection object.
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else
            {
                _print.Error("Must supply a SQL server (/h:, /host:), username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further.
                return false;
            }
        }

        /// <summary>
        /// The _azureAd method is called if the authentication type is AzureAD.
        /// This requires a SQL server, domain, username, password and module
        /// otherwise an error message is displayed.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static bool _azureAd(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary["auth"].ToLower().Equals("azuread") && argumentDictionary.ContainsKey("host") &&
                argumentDictionary.ContainsKey("domain") && argumentDictionary.ContainsKey("username") &&
                argumentDictionary.ContainsKey("password") && argumentDictionary.ContainsKey("module"))
            {
                if (!argumentDictionary["domain"].Contains("."))
                {
                    _print.Error("Domain (/d:, /domain:) must be the fully qualified domain name (domain.com).", true);
                    // Go no further.
                    return false;
                }
                else
                {
                    _gV.AuthenticationType = argumentDictionary["auth"].ToLower();
                    _gV.SqlServer = argumentDictionary["host"];
                    _gV.Domain = argumentDictionary["domain"];
                    _gV.Username = argumentDictionary["username"];
                    _gV.Password = argumentDictionary["password"];

                    // Optional arg for database.
                    if (argumentDictionary.ContainsKey("database"))
                    {
                        _gV.Database = argumentDictionary["database"].ToLower();
                    }

                    // Optional argument for port, defaults to 1433.
                    if (argumentDictionary.ContainsKey("port"))
                    {
                        _gV.Port = argumentDictionary["port"];
                    }

                    // Create the SQL connection object.
                    _gV.Connect = CreateSqlConnectionObject();
                    return true;
                }
            }
            else
            {
                _print.Error("Must supply a SQL server (/h:, /host:), domain (/d:, /domain:), username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further.
                return false;
            }
        }

        /// <summary>
        /// The _azureLocal method is called if the authentication type is AzureLocal.
        /// This requires a SQL server, username, password and module
        /// otherwise an error message is displayed.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static bool _azureLocal(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary["auth"].ToLower().Equals("azurelocal") && argumentDictionary.ContainsKey("host") &&
                argumentDictionary.ContainsKey("username") && argumentDictionary.ContainsKey("password") &&
                argumentDictionary.ContainsKey("module"))
            {
                _gV.AuthenticationType = argumentDictionary["auth"].ToLower();
                _gV.SqlServer = argumentDictionary["host"];
                _gV.Username = argumentDictionary["username"];
                _gV.Password = argumentDictionary["password"];

                // Optional arg for database.
                if (argumentDictionary.ContainsKey("database"))
                {
                    _gV.Database = argumentDictionary["database"].ToLower();
                }

                // Optional argument for port, defaults to 1433.
                if (argumentDictionary.ContainsKey("port"))
                {
                    _gV.Port = argumentDictionary["port"];
                }

                // Create the SQL connection object.
                _gV.Connect = CreateSqlConnectionObject();
                return true;
            }
            else 
            {
                _print.Error("Must supply a SQL server (/h:, /host:), username (/u:, /username:), password (/p: /password:) and module (/m:, /module:).", true);
                // Go no further.
                return false;
            }
        }
    }
}
