using System.Collections.Generic;
using System.Data.SqlClient;

namespace SQLRecon.Commands
{
    internal class GlobalVariables
    {
        private static SqlConnection _connect;
        private static string _arg0;
        private static string _arg1;
        private static string _arg2;
        private static string _authenticationType;
        private static string _database = "master";
        private static string _domain;
        private static string _impersonate;
        private static string[] _tunnelSqlServer;
        private static string _tunnelPath;
        private static string _module;
        private static string _password;
        private static string _port = "1433";
        private static string _sqlServer;
        private static string _username;

        private static bool _debug = false;

        public Dictionary<string, string> CoreCommands
        {
            get
            {
                return new Dictionary<string, string>()
                {
                    {"a", "auth"},
                    {"c", "command"},
                    {"d", "domain"},
                    {"e", "enum"},
                    {"h", "host"},
                    {"i", "iuser"},
                    {"l", "lhost"},
                    {"t", "tunnel"},
                    {"m", "module"},
                    {"o", "option"},
                    {"p", "password"},
                    {"u", "username"},
                    {"debug", "debug"},
                };
            }
        }

        public Dictionary<string, int> StandardArgumentsAndOptionCount
        {
            get
            {
                return new Dictionary<string, int>()
                {
                    {"agentstatus", 0},
                    {"checkrpc", 0},
                    {"databases", 0},
                    {"disableclr", 0},
                    {"disableole", 0},
                    {"disablexp", 0},
                    {"enableclr", 0},
                    {"enableole", 0},
                    {"enablexp", 0},
                    {"info", 0},
                    {"impersonate", 0},
                    {"links", 0},
                    {"users", 0},
                    {"whoami", 0},
                    {"agentcmd", 1},
                    {"disablerpc", 1},
                    {"enablerpc", 1},
                    {"olecmd", 1},
                    {"query", 1},
                    {"search", 1},
                    {"smb", 1},
                    {"tables", 1},
                    {"xpcmd", 1},
                    {"adsi", 2},
                    {"clr", 2},
                    {"columns", 2},
                    {"rows", 2}
                };
            }
        }

        public Dictionary<string, int> SccmArgumentsAndOptionCount
        {
            get
            {
                return new Dictionary<string, int>()
                {
                    {"scredentials", 0},
                    {"sdecryptcredentials", 0},
                    {"slogons", 0},
                    {"ssites", 0},
                    {"staskdata", 0},
                    {"stasklist", 0},
                    {"susers", 0},
                    {"saddadmin", 2},
                    {"sremoveadmin", 2}
                };
            }
        }

        public bool Debug
        {
            get
            {
                return _debug;
            }
            set
            {
                _debug = value;
            }
        }

        public string Arg0
        {
            get
            {
                return _arg0;
            }
            set
            {
                _arg0 = value;
            }
        }
        public string Arg1
        {
            get
            {
                return _arg1;
            }
            set
            {
                _arg1 = value;
            }
        }
        public string Arg2
        {
            get
            {
                return _arg2;
            }
            set
            {
                _arg2 = value;
            }
        }
        public SqlConnection Connect
        {
            get
            {
                return _connect;
            }
            set
            {
                _connect = value;
            }
        }
        public string AuthenticationType
        {
            get
            {
                return _authenticationType;
            }
            set
            {
                _authenticationType = value;
            }
        }
        public string Database
        {
            get
            {
                return _database;
            }
            set
            {
                _database = value;
            }
        }
        public string Domain
        {
            get
            {
                return _domain;
            }
            set
            {
                _domain = value;
            }
        }
        public string Impersonate
        {
            get
            {
                return _impersonate;
            }
            set
            {
                _impersonate = value;
            }
        }

        public string[] TunnelSqlServer
        {
            get
            {
                return _tunnelSqlServer;
            }
            set
            {
                _tunnelSqlServer = value;
            }
        }

        public string Module
        {
            get
            {
                return _module;
            }
            set
            {
                _module = value;
            }
        }

        public string Password
        {
            get
            {
                return _password;
            }
            set
            {
                _password = value;
            }
        }
        public string Port
        {
            get
            {
                return _port;
            }
            set
            {
                _port = value;
            }
        }
        public string SqlServer
        {
            get
            {
                return _sqlServer;
            }
            set
            {
                _sqlServer = value;
            }
        }
        public string Username
        {
            get
            {
                return _username;
            }
            set
            {
                _username = value;
            }
        }

        public string TunnelPath
        {
            get
            {
                return _tunnelPath;
            }
            set
            {
                _tunnelPath = value;
            }
        }
    }
}
