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
        private static string _linkedSqlServer;
        private static string _module;
        private static string _password;
        private static string _port = "1433";
        private static string _sqlServer;
        private static string _username;

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
                    {"m", "module"},
                    {"o", "option"},
                    {"p", "password"},
                    {"u", "username"}
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

        public Dictionary<string, int> ImpersonationArgumentsAndOptionCount
        {
            get
            {
                return new Dictionary<string, int>()
                {
                    {"iagentstatus", 1},
                    {"icheckrpc", 1},
                    {"idatabases", 1},
                    {"idisableclr", 1},
                    {"idisableole", 1},
                    {"idisablexp", 1},
                    {"ienableclr", 1},
                    {"ienableole", 1},
                    {"ienablexp", 1},
                    {"ilinks", 1},
                    {"iusers", 1},
                    {"iwhoami", 1},
                    {"iagentcmd", 2},
                    {"idisablerpc", 2},
                    {"ienablerpc", 2},
                    {"iolecmd", 2},
                    {"iquery", 2},
                    {"isearch", 2},
                    {"itables", 2},
                    {"ixpcmd", 2},
                    {"iadsi", 3},
                    {"iclr", 3},
                    {"icolumns", 3},
                    {"irows", 3}
                };
            }
        }

        public Dictionary<string, int> LinkedArgumentsAndOptionCount
        {
            get
            {
                return new Dictionary<string, int>()
                {
                    {"lagentstatus", 1},
                    {"lcheckrpc", 1},
                    {"ldatabases", 1},
                    {"ldisableclr", 1},
                    {"ldisableole", 1},
                    {"ldisablexp", 1},
                    {"lenableclr", 1},
                    {"lenableole", 1},
                    {"lenablexp", 1},
                    {"llinks", 1},
                    {"lusers", 1},
                    {"lwhoami", 1},
                    {"lagentcmd", 2},
                    {"lolecmd", 2},
                    {"lquery", 2},
                    {"lsmb", 2},
                    {"ltables", 2},
                    {"lxpcmd", 2},
                    {"ladsi", 3},
                    {"lclr", 3},
                    {"lcolumns", 3},
                    {"lsearch", 3},
                    {"lrows", 3}
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
        public string LinkedSqlServer
        {
            get
            {
                return _linkedSqlServer;
            }
            set
            {
                _linkedSqlServer = value;
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
    }
}
