using System;
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
        /// a remote SQL server using xp_cmdshell.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        public void Standard(SqlConnection con, string cmd)
        {
            try
            {
                // First check to see if xp_cmdshell is enabled.
                string sqlOutput = _config.ModuleStatus(con, "xp_cmdshell");

                if (!sqlOutput.Contains("1"))
                {
                    _print.Error("You need to enable xp_cmdshell (enablexp).", true);
                    return;
                }

                sqlOutput = _sqlQuery.ExecuteCustomQuery(con, "EXEC xp_cmdshell '" + cmd + "';");
                _printStatus(sqlOutput);
                return;
            }
            catch (Exception ex)
            {
                _print.Error($"Failed to execute command using xp_cmdshell: {ex.Message}", true);
                return;
            }
        }

        /// <summary>
        /// The Tunnel method executes an arbitrary command on
        /// a remote tunneled SQL server using xp_cmdshell.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="cmd"></param>
        /// <param name="tunnelSqlServers"></param>
        public void Tunnel(SqlConnection con, string cmd, string[] tunnelSqlServers)
        {
            try
            {
                // First check to see if xp_cmdshell is enabled.
                string sqlOutput = _config.TunnelModuleStatus(con, "xp_cmdshell", tunnelSqlServers);
                if (!sqlOutput.Contains("1"))
                {
                    _print.Error("You need to enable xp_cmdshell (enablexp).", true);
                    return;
                }

                sqlOutput = _sqlQuery.ExecuteTunnelCustomQuery(con, tunnelSqlServers, $"select 1; exec master..xp_cmdshell '{cmd}';");
                _printStatus(sqlOutput);
            }
            catch (Exception ex)
            {
                _print.Error($"Failed to execute command on tunneled server using xp_cmdshell: {ex.Message}", true);
                return;
            }
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