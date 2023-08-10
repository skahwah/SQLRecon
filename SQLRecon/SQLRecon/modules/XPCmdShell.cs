using System.Data.SqlClient;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class XpCmdShell
    {
        private static readonly Configure _config = new();
        private static readonly PrintUtils _print = new();
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The Standard method executes an arbitrary command on 
        /// a remoe SQL server using xp_cmdshell.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        public void Standard(SqlConnection con, string cmd)
        {

            // First check to see if xp_cmdshell is enabled.
            string sqlOutput = _config.ModuleStatus(con, "xp_cmdshell");

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable xp_cmdshell (enablexp).", true);
                // Go no futher.
                return;
            }

            sqlOutput = _sqlQuery.ExecuteCustomQuery(con, "EXEC xp_cmdshell '" + cmd + "';");

            _printStatus(sqlOutput);
        }

        /// <summary>
        /// The Impersonate method executes an arbitrary command on 
        /// a remote SQL server using xp_cmdshell with impersonation.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="impersonate"></param>
        public void Impersonate(SqlConnection con, string cmd, string impersonate)
        {
            // First check to see if xp_cmdshell is enabled.
            string sqlOutput = _config.ModuleStatus(con, "xp_cmdshell", impersonate);

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable xp_cmdshell (ienablexp).", true);
                // Go no futher.
                return;
            }

            sqlOutput = _sqlQuery.ExecuteImpersonationCustomQuery(con, impersonate, "EXEC xp_cmdshell '" + cmd + "';");

            _printStatus(sqlOutput);
        }

        /// <summary>
        /// The Linked method executes an arbitrary command on 
        /// a remote linked SQL server using xp_cmdshell.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="linkedSqlServer"></param>
        public void Linked(SqlConnection con, string cmd, string linkedSqlServer)
        {
            // First check to see if xp_cmdshell is enabled.
            string sqlOutput = _config.LinkedModuleStatus(con, "xp_cmdshell", linkedSqlServer);

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable xp_cmdshell (lenablexp).", true);
                // Go no futher.
                return;
            }

            sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "select 1; exec master..xp_cmdshell ''" + cmd + "''");

            _printStatus(sqlOutput);
        }

        /// <summary>
        /// The _printStatus method will display the status of the 
        /// xp_cmdshell command execution.
        /// </summary>
        /// <param name="sqlOutput"></param>
        private void _printStatus(string sqlOutput)
        {
            if (sqlOutput.Contains("permission"))
            {
                _print.Error("The current user does not have permissions to enable xp_cmdshell commands.", true);
            }
            else if (sqlOutput.Contains("blocked"))
            {
                _print.Error("You need to enable xp_cmdshell.", true);
            }
            else
            {
                _print.IsOutputEmpty(sqlOutput, true);
            }
        }
    }
}