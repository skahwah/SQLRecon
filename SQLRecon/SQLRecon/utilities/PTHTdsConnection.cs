using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace SQLRecon.Utilities
{
    /// <summary>
    /// PTHTdsConnection implements a minimal TDS client that authenticates using
    /// NTLM pass-the-hash over a raw TCP connection. No Windows auth APIs are used,
    /// so no elevated privileges are required.
    /// </summary>
    internal class PTHTdsConnection : IDisposable
    {
        // TDS packet type constants
        private const byte PackSqlBatch   = 0x01;
        private const byte PackLogin7     = 0x10;
        private const byte PackSspi       = 0x11;
        private const byte PackPreLogin   = 0x12;

        // TDS token type constants
        private const byte TokColMetaData = 0x81;
        private const byte TokError       = 0xAA;
        private const byte TokInfo        = 0xAB;
        private const byte TokLoginAck    = 0xAD;
        private const byte TokEnvChange   = 0xE3;
        private const byte TokSspi        = 0xED;
        private const byte TokRow         = 0xD1;
        private const byte TokNbcRow      = 0xD2;
        private const byte TokDone        = 0xFD;
        private const byte TokDoneProc    = 0xFE;
        private const byte TokDoneInProc  = 0xFF;
        private const byte TokReturnValue = 0xAC;
        private const byte TokReturnStat  = 0x79;
        private const byte TokTabName    = 0xA4;
        private const byte TokColInfo    = 0xA5;
        private const byte TokOrder     = 0xA9;

        private TcpClient _tcp;
        private NetworkStream _stream;
        private byte _packetId = 1;

        // Column descriptor used when parsing result sets
        private struct ColInfo
        {
            public string Name;
            // How to read the value from the ROW token
            public ColReadMode ReadMode;
            public int FixedLen;      // for ReadMode.Fixed
            public bool IsUnicode;    // for ShortLen/Plp: true = UTF-16LE (NVARCHAR), false = ANSI (VARCHAR)
            public bool IsDateTime;   // for Fixed/ByteLen: decode as SQL Server datetime binary
            public bool IsBit;        // for Fixed/ByteLen: return "True"/"False" instead of "0"/"1"
            public bool IsMoney;      // for Fixed/ByteLen: decode as SQL Server money (high32 | low32) / 10000
            public bool IsFloat;      // for Fixed/ByteLen: decode as IEEE 754 float/double
            public bool IsDecimal;    // for ByteLen: decode as sign + LE big-int / 10^Scale
            public int  Scale;        // for IsDecimal: number of decimal places
            public bool IsGuid;       // for ByteLen: format 16 bytes as GUID string
            public bool IsBinary;     // for ShortLen/Plp: return "[binary data]" instead of text decode
        }

        private enum ColReadMode { Fixed, ByteLen, ShortLen, Plp, Skip, SqlVariant }

        /// <summary>
        /// Connects to the SQL Server and authenticates using NTLM with the provided NT hash.
        /// Throws on authentication failure or network error.
        /// </summary>
        internal PTHTdsConnection(string server, int port, string database,
                                  string domain, string username, byte[] ntHash)
        {
            _tcp = new TcpClient();
            _tcp.SendTimeout    = 10000;
            _tcp.ReceiveTimeout = 10000;
            _tcp.Connect(server, port);
            _stream = _tcp.GetStream();

            _sendPreLogin();
            _readPreLoginResponse();
            _login(server, database, domain, username, ntHash);

            // SqlClient sends these SET options automatically after login.
            // OPENQUERY (heterogeneous queries) requires ANSI_NULLS and ANSI_WARNINGS.
            // QUOTED_IDENTIFIER is required for bracket-free identifier quoting.
            // The others match SqlClient defaults for consistent behaviour.
            _executeRaw("SET ANSI_NULLS ON; SET ANSI_WARNINGS ON; SET ANSI_PADDING ON; " +
                        "SET ANSI_NULL_DFLT_ON ON; SET CONCAT_NULL_YIELDS_NULL ON; " +
                        "SET QUOTED_IDENTIFIER ON;");

            // Remove the receive timeout after login so that long-running queries
            // (e.g. the CLR LDAP server listener in the ADSI module) don't time out.
            _tcp.ReceiveTimeout = 0;
        }

        // ── PreLogin ─────────────────────────────────────────────────────────

        private void _sendPreLogin()
        {
            // 5 option tokens (5×5=25 bytes) + terminator (1) + data (13) = 39 bytes payload
            // VERSION(6) + ENCRYPTION(1) + INSTOPT(1) + THREADID(4) + MARS(1) = 13
            const int optCount   = 5;
            const int hdrBytes   = optCount * 5 + 1; // 26
            const int versionOff = hdrBytes;          // 26
            const int encryptOff = versionOff + 6;    // 32
            const int instOff    = encryptOff + 1;    // 33
            const int threadOff  = instOff    + 1;    // 34
            const int marsOff    = threadOff  + 4;    // 38
            const int payloadLen = marsOff    + 1;    // 39

            byte[] pl = new byte[payloadLen];
            int p = 0;

            // PreLogin option token headers use big-endian offset and length (MS-TDS spec 2.2.6.4)

            // VERSION token
            pl[p++] = 0x00;
            NtlmHelper.WriteU16BE(pl, p, (ushort)versionOff); p += 2;
            NtlmHelper.WriteU16BE(pl, p, 6);                   p += 2;

            // ENCRYPTION token
            pl[p++] = 0x01;
            NtlmHelper.WriteU16BE(pl, p, (ushort)encryptOff); p += 2;
            NtlmHelper.WriteU16BE(pl, p, 1);                   p += 2;

            // INSTOPT token
            pl[p++] = 0x02;
            NtlmHelper.WriteU16BE(pl, p, (ushort)instOff); p += 2;
            NtlmHelper.WriteU16BE(pl, p, 1);                p += 2;

            // THREADID token
            pl[p++] = 0x03;
            NtlmHelper.WriteU16BE(pl, p, (ushort)threadOff); p += 2;
            NtlmHelper.WriteU16BE(pl, p, 4);                  p += 2;

            // MARS token
            pl[p++] = 0x04;
            NtlmHelper.WriteU16BE(pl, p, (ushort)marsOff); p += 2;
            NtlmHelper.WriteU16BE(pl, p, 1);                p += 2;

            // TERMINATOR
            pl[p++] = 0xFF;

            // VERSION data: 9.00.0000.00 (arbitrary client version)
            pl[p++] = 9; pl[p++] = 0;
            NtlmHelper.WriteU16(pl, p, 0); p += 2;
            NtlmHelper.WriteU16(pl, p, 0); p += 2;

            // ENCRYPTION: 0x02 = ENCRYPT_NOT_SUP
            pl[p++] = 0x02;

            // INSTOPT: empty instance (null terminator)
            pl[p++] = 0x00;

            // THREADID: current managed thread ID
            NtlmHelper.WriteU32(pl, p,
                (uint)System.Threading.Thread.CurrentThread.ManagedThreadId);
            p += 4;

            // MARS: disabled
            pl[p] = 0x00;

            _sendPacket(PackPreLogin, pl);
        }

        private void _readPreLoginResponse()
        {
            byte[] resp = _readMessage();
            // Scan the server's PreLogin option tokens (big-endian offsets/lengths per MS-TDS spec)
            // looking for the ENCRYPTION token (0x01) to check if TLS is required.
            int i = 0;
            while (i < resp.Length - 4)
            {
                byte tok = resp[i];
                if (tok == 0xFF) break; // TERMINATOR

                // Read big-endian offset and length
                ushort off = (ushort)((resp[i+1] << 8) | resp[i+2]);
                // ushort len = (ushort)((resp[i+3] << 8) | resp[i+4]); // not needed
                i += 5;

                if (tok == 0x01 && off < resp.Length) // ENCRYPTION
                {
                    byte enc = resp[off];
                    if (enc == 0x01 || enc == 0x03)
                        throw new Exception(
                            "SQL Server requires TLS encryption. " +
                            "PTH auth via raw TDS does not support encrypted connections. " +
                            "Disable 'Force Encryption' on the target SQL Server or use /auth:windomain.");
                    break;
                }
            }
        }

        // ── Login7 + NTLM ────────────────────────────────────────────────────

        private void _login(string server, string database, string domain, string username, byte[] ntHash)
        {
            byte[] ntlmType1 = NtlmHelper.BuildType1();

            byte[] loginPkt = _buildLogin7(server, database, ntlmType1);
            _sendPacket(PackLogin7, loginPkt);

            // Server responds with NTLM Type 2 challenge inside SSPI token
            byte[] resp  = _readMessage();
            byte[] type2 = _extractSspiToken(resp);
            if (type2 == null)
                throw new Exception(_extractErrorMessage(resp) ?? "No NTLM challenge received from server.");

            var (serverChallenge, targetInfo, serverFlags) = NtlmHelper.ParseType2(type2);
            byte[] ntlmType3 = NtlmHelper.BuildType3(domain, username, ntHash,
                                                      serverChallenge, targetInfo, serverFlags);

            // Send Type 3 as a TDS SSPI message
            _sendPacket(PackSspi, ntlmType3);

            // Read auth result
            byte[] authResp = _readMessage();
            if (!_hasLoginAck(authResp))
            {
                string err = _extractErrorMessage(authResp);
                throw new Exception(err ?? $"Authentication failed for '{domain}\\{username}'.");
            }
        }

        private byte[] _buildLogin7(string server, string database, byte[] sspiData)
        {
            byte[] hostBytes   = Encoding.Unicode.GetBytes(Environment.MachineName);
            byte[] appBytes    = Encoding.Unicode.GetBytes("SQLRecon");
            byte[] serverBytes = Encoding.Unicode.GetBytes(server);
            byte[] dbBytes     = Encoding.Unicode.GetBytes(database);

            // Fixed header for TDS 7.2 = 94 bytes
            // Layout: 4+4+4+4+4+4+1+1+1+1+4+4 = 36 bytes scalar fields
            //       + 13 × (2+2) = 52 bytes offset/length pairs
            //       + 6 bytes ClientID = 94 bytes total
            const int hdrSize = 94;

            int hostOff   = hdrSize;
            int appOff    = hostOff   + hostBytes.Length;
            int serverOff = appOff    + appBytes.Length;
            int dbOff     = serverOff + serverBytes.Length;
            int sspiOff   = dbOff     + dbBytes.Length;
            int total     = sspiOff   + sspiData.Length;

            byte[] msg = new byte[total];

            NtlmHelper.WriteU32(msg, 0,  (uint)total);      // Length
            NtlmHelper.WriteU32(msg, 4,  0x72090002);       // TDS 7.2
            NtlmHelper.WriteU32(msg, 8,  0x00001000);       // PacketSize = 4096
            NtlmHelper.WriteU32(msg, 12, 0x06000000);       // ClientProgVer
            NtlmHelper.WriteU32(msg, 16, (uint)System.Diagnostics.Process.GetCurrentProcess().Id);
            // ConnectionID = 0
            msg[24] = 0xE0;                                 // OptionFlags1
            msg[25] = 0x80;                                 // OptionFlags2: fIntSecurity (bit 7)
            // TypeFlags, OptionFlags3 = 0
            // ClientTimeZone = 0
            msg[32] = 0x09; msg[33] = 0x04;                // ClientLCID = 0x00000409 (en-US)

            // Offset/Length pairs (each 4 bytes: 2-byte offset + 2-byte count in chars)
            // ibHostName / cchHostName
            NtlmHelper.WriteU16(msg, 36, (ushort)hostOff);
            NtlmHelper.WriteU16(msg, 38, (ushort)(hostBytes.Length / 2));
            // ibUserName / cchUserName = 0 (SSPI)
            NtlmHelper.WriteU16(msg, 40, (ushort)appOff);
            NtlmHelper.WriteU16(msg, 42, 0);
            // ibPassword / cchPassword = 0 (SSPI)
            NtlmHelper.WriteU16(msg, 44, (ushort)appOff);
            NtlmHelper.WriteU16(msg, 46, 0);
            // ibAppName / cchAppName
            NtlmHelper.WriteU16(msg, 48, (ushort)appOff);
            NtlmHelper.WriteU16(msg, 50, (ushort)(appBytes.Length / 2));
            // ibServerName / cchServerName
            NtlmHelper.WriteU16(msg, 52, (ushort)serverOff);
            NtlmHelper.WriteU16(msg, 54, (ushort)(serverBytes.Length / 2));
            // ibUnused / cbUnused = 0
            // ibCltIntName / cbCltIntName = 0
            // ibLanguage / cchLanguage = 0
            // ibDatabase / cchDatabase
            NtlmHelper.WriteU16(msg, 68, (ushort)dbOff);
            NtlmHelper.WriteU16(msg, 70, (ushort)(dbBytes.Length / 2));
            // ClientID (6 bytes at offset 72) = zeros
            // ibSSPI / cbSSPI
            NtlmHelper.WriteU16(msg, 78, (ushort)sspiOff);
            NtlmHelper.WriteU16(msg, 80, (ushort)sspiData.Length);
            // ibAtchDBFile / cbAtchDBFile = 0
            // ibChangePassword / cchChangePassword = 0 (offset 86)
            // cbSSPILong = 0 (offset 90)

            // Payload
            Buffer.BlockCopy(hostBytes,   0, msg, hostOff,   hostBytes.Length);
            Buffer.BlockCopy(appBytes,    0, msg, appOff,    appBytes.Length);
            Buffer.BlockCopy(serverBytes, 0, msg, serverOff, serverBytes.Length);
            Buffer.BlockCopy(dbBytes,     0, msg, dbOff,     dbBytes.Length);
            Buffer.BlockCopy(sspiData,    0, msg, sspiOff,   sspiData.Length);

            return msg;
        }

        // ── Query execution ──────────────────────────────────────────────────

        /// <summary>
        /// Executes a SQL statement and discards the result.
        /// Mirrors the contract of Sql.NonQuery().
        /// </summary>
        /// <summary>
        /// Sets the TCP receive timeout in milliseconds. Use 0 for no timeout.
        /// </summary>
        internal void SetReceiveTimeout(int ms) => _tcp.ReceiveTimeout = ms;

        internal void ExecuteNonQuery(string sql)
        {
            _executeRaw(sql);
        }

        /// <summary>
        /// Executes a SQL query and returns the first column of the first row as a string.
        /// Mirrors the contract of Sql.Query().
        /// </summary>
        internal string ExecuteQuery(string sql)
        {
            var (columns, rows, error) = _executeRaw(sql);
            if (error != null) return error;
            if (rows.Count == 0 || columns.Count == 0) return "";
            return rows[0][0] ?? "";
        }

        /// <summary>
        /// Executes a SQL query and returns all results formatted as a markdown table.
        /// Mirrors the contract of Sql.CustomQuery().
        /// </summary>
        internal string ExecuteCustomQuery(string sql)
        {
            var (columns, rows, error) = _executeRaw(sql);
            if (error != null) return error;
            if (columns.Count == 0) return "";
            return _toMarkdownTable(columns, rows);
        }

        /// <summary>
        /// Sends a SQL batch to SQL Server but does NOT read the response.
        /// The caller must later call ReceiveQueryResult() to collect the result.
        /// Used by the ADSI module to start the CLR LDAP listener before triggering
        /// the LDAP solicitation on a second connection, avoiding the Task.Run timing
        /// race where run_ldap_server fires before SQL Server starts the LDAP listener.
        /// </summary>
        internal void SendOnly(string sql)
        {
            _sendPacket(PackSqlBatch, _buildBatchPayload(sql));
        }

        /// <summary>
        /// Reads and returns the pending query result from a prior SendOnly() call.
        /// Returns the first cell of the first row, or an error string.
        /// </summary>
        internal string ReceiveQueryResult()
        {
            try
            {
                byte[] resp = _readMessage();
                var (columns, rows, error) = _parseTokenStream(resp);
                if (error != null) return error;
                if (rows.Count == 0 || columns.Count == 0) return "";
                return rows[0][0] ?? "";
            }
            catch (Exception ex)
            {
                return Print.Error(ex.Message);
            }
        }

        private byte[] _buildBatchPayload(string sql)
        {
            byte[] sqlBytes = Encoding.Unicode.GetBytes(sql);

            // TDS 7.2+ requires an ALL_HEADERS section before the SQL text in every SQLBatch packet.
            // Without it SQL Server returns "TDS headers contained errors."
            // Format: TotalLength(4) + HeaderLength(4) + HeaderType(2) + TransactionDescriptor(8) + OutstandingRequestCount(4) = 22 bytes
            byte[] allHeaders = new byte[22];
            NtlmHelper.WriteU32(allHeaders, 0,  22); // TotalLength
            NtlmHelper.WriteU32(allHeaders, 4,  18); // HeaderLength
            NtlmHelper.WriteU16(allHeaders, 8,  0x0002); // HeaderType: TRANSACTION_DESCRIPTOR
            // TransactionDescriptor (8 bytes at offset 10) = 0 → autocommit
            NtlmHelper.WriteU32(allHeaders, 18, 1);  // OutstandingRequestCount

            byte[] payload = new byte[allHeaders.Length + sqlBytes.Length];
            Buffer.BlockCopy(allHeaders, 0, payload, 0,               allHeaders.Length);
            Buffer.BlockCopy(sqlBytes,   0, payload, allHeaders.Length, sqlBytes.Length);
            return payload;
        }

        private (List<ColInfo> columns, List<string[]> rows, string error) _executeRaw(string sql)
        {
            byte[] payload = _buildBatchPayload(sql);

            try
            {
                _sendPacket(PackSqlBatch, payload);
                byte[] resp = _readMessage();
                return _parseTokenStream(resp);
            }
            catch (Exception ex)
            {
                // Surface network/parse errors as visible error strings instead of
                // propagating to Program.Main's bare catch (Exception) {} which silently
                // swallows them and produces no output.
                string msg = Print.Error(ex.Message);
                return (new List<ColInfo>(), new List<string[]>(), msg);
            }
        }

        // ── Token stream parser ───────────────────────────────────────────────

        private (List<ColInfo> columns, List<string[]> rows, string error) _parseTokenStream(byte[] ts)
        {
            var columns = new List<ColInfo>();
            var rows    = new List<string[]>();
            string firstError = null;
            int pos = 0;

            while (pos < ts.Length)
            {
                byte tok = ts[pos++];

                switch (tok)
                {
                    case TokColMetaData:
                        columns = _readColMetaData(ts, ref pos);
                        break;

                    case TokRow:
                        if (columns.Count > 0)
                            rows.Add(_readRow(ts, ref pos, columns));
                        break;

                    case TokNbcRow:
                        if (columns.Count > 0)
                            rows.Add(_readNbcRow(ts, ref pos, columns));
                        break;

                    case TokError:
                    {
                        ushort len   = NtlmHelper.ReadU16(ts, pos); pos += 2;
                        pos += 4 + 1 + 1; // Number + State + Class
                        ushort msgLen = NtlmHelper.ReadU16(ts, pos); pos += 2;
                        string msg = Encoding.Unicode.GetString(ts, pos, msgLen * 2); pos += msgLen * 2;
                        // skip ServerName, ProcName, LineNumber
                        int snLen = ts[pos++]; pos += snLen * 2;
                        int pnLen = ts[pos++]; pos += pnLen * 2;
                        pos += 4; // LineNumber
                        if (firstError == null) firstError = Print.Error(msg);
                        break;
                    }

                    case TokInfo:
                    {
                        ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                        pos += len;
                        break;
                    }

                    case TokEnvChange:
                    {
                        ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                        pos += len;
                        break;
                    }

                    case TokLoginAck:
                    {
                        ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                        pos += len;
                        break;
                    }

                    case TokTabName:
                    case TokColInfo:
                    case TokOrder:
                    {
                        // TABNAME/COLINFO/ORDER all use a 2-byte length prefix followed by data
                        ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                        pos += len;
                        break;
                    }

                    case TokReturnValue:
                    {
                        // Skip: ParamOrdinal(2)+ParamName(1+N)+Status(1)+UserType(4)+Flags(2)+TypeInfo+Value
                        // Simplest: skip by reading 2-byte length that follows for some token types.
                        // ReturnValue doesn't have a simple length prefix; skip until DONE.
                        // Safe fallback: stop parsing (remaining data is unneeded)
                        pos = ts.Length;
                        break;
                    }

                    case TokReturnStat:
                        pos += 4;
                        break;

                    case TokDone:
                    case TokDoneProc:
                    case TokDoneInProc:
                        pos += 12; // Status(2)+CurCmd(2)+DoneRowCount(8) — TDS 7.2+ uses 8-byte row count
                        break;

                    default:
                        // Unknown token — stop parsing
                        pos = ts.Length;
                        break;
                }
            }

            return (columns, rows, firstError);
        }

        private List<ColInfo> _readColMetaData(byte[] ts, ref int pos)
        {
            var cols = new List<ColInfo>();
            ushort count = NtlmHelper.ReadU16(ts, pos); pos += 2;

            if (count == 0xFFFF) return cols; // no metadata

            for (int i = 0; i < count; i++)
            {
                var col = new ColInfo();
                pos += 4; // UserType (TDS 7.2+)
                pos += 2; // Flags

                byte typeCode = ts[pos++];
                _classifyType(typeCode, ts, ref pos, ref col);

                // ColName: 1-byte length (char count) + Unicode chars
                int nameLen = ts[pos++];
                col.Name = Encoding.Unicode.GetString(ts, pos, nameLen * 2);
                pos += nameLen * 2;

                cols.Add(col);
            }

            return cols;
        }

        private void _classifyType(byte typeCode, byte[] ts, ref int pos, ref ColInfo col)
        {
            switch (typeCode)
            {
                // ── Fixed-length types ───────────────────────────────────────
                case 0x1F: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 0;  break; // NULL
                case 0x30: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 1;  break; // TINYINT
                case 0x32: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 1; col.IsBit = true; break; // BIT
                case 0x34: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 2;  break; // SMALLINT
                case 0x38: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 4;  break; // INT (INT4TYPE)
                case 0x3A: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 4; col.IsDateTime = true; break; // SMALLDATETIME
                case 0x3B: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 4; col.IsFloat = true; break; // REAL
                case 0x3C: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 8; col.IsMoney = true; break; // MONEY (MONEYTYPE)
                case 0x3D: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 8; col.IsDateTime = true; break; // DATETIME
                case 0x3E: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 8; col.IsFloat = true; break; // FLOAT
                case 0x7A: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 4; col.IsMoney = true; break; // SMALLMONEY
                case 0x7C: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 8; col.IsMoney = true; break; // MONEY
                case 0x7F: col.ReadMode = ColReadMode.Fixed; col.FixedLen = 8;  break; // BIGINT

                // ── 1-byte length prefix types ───────────────────────────────
                // TypeInfo: 1-byte MaxLen
                case 0x24: pos += 1; col.ReadMode = ColReadMode.ByteLen; col.IsGuid = true; break; // UNIQUEIDENTIFIER
                case 0x26: pos += 1; col.ReadMode = ColReadMode.ByteLen; break; // INTN (int any size)
                case 0x28: pos += 1; col.ReadMode = ColReadMode.ByteLen; break; // DATEN
                case 0x6C: pos += 1; col.ReadMode = ColReadMode.ByteLen; col.IsMoney = true; break; // MONEYN
                case 0x6D: pos += 1; col.ReadMode = ColReadMode.ByteLen; col.IsFloat = true; break; // FLTN
                case 0x6E: pos += 1; col.ReadMode = ColReadMode.ByteLen; col.IsMoney = true; break; // MONEYN alt
                case 0x6F: pos += 1; col.ReadMode = ColReadMode.ByteLen; col.IsDateTime = true; break; // DATETIMN
                case 0x68: pos += 1; col.ReadMode = ColReadMode.ByteLen; col.IsBit = true; break; // BITN

                // TypeInfo: 1-byte Scale + 1-byte MaxLen
                case 0x29: pos += 2; col.ReadMode = ColReadMode.ByteLen; break; // TIME
                case 0x2A: pos += 2; col.ReadMode = ColReadMode.ByteLen; break; // DATETIME2N
                case 0x2B: pos += 2; col.ReadMode = ColReadMode.ByteLen; break; // DATETIMEOFFSETN

                // TypeInfo: 1-byte MaxLen + 1-byte Precision + 1-byte Scale
                case 0x6A: // DECIMALN
                case 0x6B: // NUMERICN
                {
                    pos += 2; // skip MaxLen and Precision
                    col.Scale = ts[pos++]; // read Scale
                    col.ReadMode = ColReadMode.ByteLen;
                    col.IsDecimal = true;
                    break;
                }

                // ── 2-byte length prefix types ───────────────────────────────
                // TypeInfo: 2-byte MaxLen (0xFFFF = MAX → PLP)
                case 0xA5: // BIGVARBINARY
                {
                    ushort maxLen = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    col.IsBinary = true;
                    col.ReadMode = maxLen == 0xFFFF ? ColReadMode.Plp : ColReadMode.ShortLen;
                    break;
                }
                case 0xAD: // BIGBINARY
                    pos += 2;
                    col.IsBinary = true;
                    col.ReadMode = ColReadMode.ShortLen;
                    break;
                case 0xA7: // VARCHAR
                {
                    ushort maxLen = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    pos += 5; // Collation
                    col.IsUnicode = false;
                    col.ReadMode = maxLen == 0xFFFF ? ColReadMode.Plp : ColReadMode.ShortLen;
                    break;
                }
                case 0xAF: // CHAR
                    pos += 2 + 5; // MaxLen + Collation
                    col.IsUnicode = false;
                    col.ReadMode = ColReadMode.ShortLen;
                    break;
                case 0xE7: // NVARCHAR
                {
                    ushort maxLen = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    pos += 5; // Collation
                    col.IsUnicode = true;
                    col.ReadMode = maxLen == 0xFFFF ? ColReadMode.Plp : ColReadMode.ShortLen;
                    break;
                }
                case 0xEF: // NCHAR
                    pos += 2 + 5; // MaxLen + Collation
                    col.IsUnicode = true;
                    col.ReadMode = ColReadMode.ShortLen;
                    break;
                case 0x62: // SQL_VARIANT
                    pos += 4; // MaxLen
                    col.ReadMode = ColReadMode.SqlVariant;
                    break;

                // ── Legacy long types (TEXT/IMAGE/NTEXT) ─────────────────────
                case 0x22: // IMAGE
                case 0x23: // TEXT
                case 0x63: // NTEXT
                    pos += 4; // MaxLen
                    pos += 5; // Collation (TEXT/NTEXT) or skip for IMAGE
                    col.ReadMode = ColReadMode.Skip;
                    break;

                default:
                    // Unknown type: mark as skip and hope for the best
                    col.ReadMode = ColReadMode.Skip;
                    break;
            }
        }

        private string[] _readRow(byte[] ts, ref int pos, List<ColInfo> cols)
        {
            string[] row = new string[cols.Count];
            for (int i = 0; i < cols.Count; i++)
                row[i] = _readColValue(ts, ref pos, cols[i]);
            return row;
        }

        private string[] _readNbcRow(byte[] ts, ref int pos, List<ColInfo> cols)
        {
            // NBC (Null Bitmap Compressed) row: null bitmap precedes the column data
            int bitmapBytes = (cols.Count + 7) / 8;
            byte[] bitmap = new byte[bitmapBytes];
            Buffer.BlockCopy(ts, pos, bitmap, 0, bitmapBytes);
            pos += bitmapBytes;

            string[] row = new string[cols.Count];
            for (int i = 0; i < cols.Count; i++)
            {
                bool isNull = (bitmap[i / 8] & (1 << (i % 8))) != 0;
                if (isNull)
                    row[i] = "";
                else
                    row[i] = _readColValue(ts, ref pos, cols[i]);
            }
            return row;
        }

        private string _readColValue(byte[] ts, ref int pos, ColInfo col)
        {
            switch (col.ReadMode)
            {
                case ColReadMode.Fixed:
                {
                    if (col.FixedLen == 0) return "";
                    byte[] raw = new byte[col.FixedLen];
                    Buffer.BlockCopy(ts, pos, raw, 0, col.FixedLen);
                    pos += col.FixedLen;
                    if (col.IsDateTime) return _decodeDateTime(raw, 0, col.FixedLen);
                    if (col.IsBit) return raw[0] != 0 ? "True" : "False";
                    if (col.IsMoney) return _decodeMoney(raw, col.FixedLen);
                    if (col.IsFloat)
                    {
                        if (col.FixedLen == 4) return BitConverter.ToSingle(raw, 0).ToString();
                        if (col.FixedLen == 8) return BitConverter.ToDouble(raw, 0).ToString();
                    }
                    return _fixedToString(raw, col.FixedLen);
                }

                case ColReadMode.ByteLen:
                {
                    int len = ts[pos++];
                    if (len == 0) return "";
                    if (col.IsDateTime) { string dt = _decodeDateTime(ts, pos, len); pos += len; return dt; }
                    if (col.IsBit) { bool b = ts[pos] != 0; pos += len; return b ? "True" : "False"; }
                    if (col.IsMoney)
                    {
                        byte[] raw = new byte[len];
                        Buffer.BlockCopy(ts, pos, raw, 0, len);
                        pos += len;
                        return _decodeMoney(raw, len);
                    }
                    if (col.IsFloat)
                    {
                        byte[] raw = new byte[len];
                        Buffer.BlockCopy(ts, pos, raw, 0, len);
                        pos += len;
                        if (len == 4) return BitConverter.ToSingle(raw, 0).ToString();
                        if (len == 8) return BitConverter.ToDouble(raw, 0).ToString();
                        return "";
                    }
                    if (col.IsDecimal)
                    {
                        // Format: 1 sign byte (0x00=negative, 0x01=positive) + (len-1) bytes LE big-int magnitude
                        bool negative = ts[pos] == 0x00;
                        decimal magnitude = 0;
                        decimal multiplier = 1;
                        for (int j = 0; j < len - 1; j++)
                        {
                            magnitude += ts[pos + 1 + j] * multiplier;
                            multiplier *= 256;
                        }
                        if (negative) magnitude = -magnitude;
                        decimal divisor = 1;
                        for (int j = 0; j < col.Scale; j++) divisor *= 10;
                        pos += len;
                        return (magnitude / divisor).ToString("F" + col.Scale);
                    }
                    if (col.IsGuid && len == 16)
                    {
                        byte[] guidBytes = new byte[16];
                        Buffer.BlockCopy(ts, pos, guidBytes, 0, 16);
                        pos += 16;
                        return new Guid(guidBytes).ToString();
                    }
                    // For non-text types (int, float, etc.) try to interpret as number
                    string val = _bytesToScalar(ts, pos, len);
                    pos += len;
                    return val;
                }

                case ColReadMode.ShortLen:
                {
                    ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    if (len == 0xFFFF) return ""; // NULL
                    if (len == 0) return "";
                    if (col.IsBinary) { pos += len; return "[binary data]"; }
                    string val = col.IsUnicode
                        ? Encoding.Unicode.GetString(ts, pos, len)
                        : Encoding.Default.GetString(ts, pos, len);
                    pos += len;
                    return val;
                }

                case ColReadMode.Plp:
                    return _readPlp(ts, ref pos, col.IsUnicode, col.IsBinary);

                case ColReadMode.SqlVariant:
                    return _readSqlVariant(ts, ref pos);

                case ColReadMode.Skip:
                default:
                    return "";
            }
        }

        private string _fixedToString(byte[] raw, int len)
        {
            switch (len)
            {
                case 1: return raw[0].ToString();
                case 2: return ((short)(raw[0] | (raw[1] << 8))).ToString();
                case 4: return ((int)(raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24))).ToString();
                case 8:
                {
                    long v = 0;
                    for (int i = 0; i < 8; i++) v |= ((long)raw[i] << (8 * i));
                    return v.ToString();
                }
                default: return BitConverter.ToString(raw).Replace("-", "");
            }
        }

        private string _decodeMoney(byte[] raw, int len)
        {
            // SQL Server money wire format: high int32 (LE) + low uint32 (LE), combined value / 10000
            // smallmoney (4 bytes): signed int32 / 10000
            if (len == 8)
            {
                int hi = raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24);
                uint lo = (uint)(raw[4] | (raw[5] << 8) | (raw[6] << 16) | (raw[7] << 24));
                long moneyRaw = ((long)hi << 32) | lo;
                return (moneyRaw / 10000.0).ToString("F4");
            }
            if (len == 4)
            {
                int v = raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24);
                return (v / 10000.0).ToString("F4");
            }
            return "";
        }

        private string _decodeDateTime(byte[] ts, int pos, int len)
        {
            try
            {
                if (len == 8)
                {
                    // datetime: signed int32 days since 1900-01-01, then uint32 1/300-second ticks since midnight
                    int days = ts[pos] | (ts[pos+1] << 8) | (ts[pos+2] << 16) | (ts[pos+3] << 24);
                    uint ticks = (uint)(ts[pos+4] | (ts[pos+5] << 8) | (ts[pos+6] << 16) | (ts[pos+7] << 24));
                    DateTime dt = new DateTime(1900, 1, 1).AddDays(days).AddSeconds((double)ticks / 300.0);
                    return dt.ToString("M/d/yyyy h:mm:ss tt");
                }
                else if (len == 4)
                {
                    // smalldatetime: uint16 days since 1900-01-01, uint16 minutes since midnight
                    ushort days    = (ushort)(ts[pos] | (ts[pos+1] << 8));
                    ushort minutes = (ushort)(ts[pos+2] | (ts[pos+3] << 8));
                    DateTime dt = new DateTime(1900, 1, 1).AddDays(days).AddMinutes(minutes);
                    return dt.ToString("M/d/yyyy h:mm:ss tt");
                }
            }
            catch { }
            return "";
        }

        private string _bytesToScalar(byte[] ts, int pos, int len)
        {
            switch (len)
            {
                case 1: return ts[pos].ToString();
                case 2: return ((short)(ts[pos] | (ts[pos+1] << 8))).ToString();
                case 4:
                {
                    int v = ts[pos] | (ts[pos+1] << 8) | (ts[pos+2] << 16) | (ts[pos+3] << 24);
                    return v.ToString();
                }
                case 8:
                {
                    long v = 0;
                    for (int i = 0; i < 8; i++) v |= ((long)ts[pos+i] << (8 * i));
                    return v.ToString();
                }
                default:
                    return Encoding.Unicode.GetString(ts, pos, len);
            }
        }

        private string _readPlp(byte[] ts, ref int pos, bool isUnicode = true, bool isBinary = false)
        {
            // PLP: 8-byte total length, then chunks
            ulong totalLen = 0;
            for (int i = 0; i < 8; i++) totalLen |= ((ulong)ts[pos+i] << (8*i));
            pos += 8;

            if (totalLen == 0xFFFFFFFFFFFFFFFF) return ""; // NULL

            if (isBinary)
            {
                // Skip all chunks without decoding
                while (true)
                {
                    uint chunkLen = NtlmHelper.ReadU32(ts, pos); pos += 4;
                    if (chunkLen == 0) break;
                    pos += (int)chunkLen;
                }
                return "[binary data]";
            }

            var sb = new StringBuilder();
            while (true)
            {
                uint chunkLen = NtlmHelper.ReadU32(ts, pos); pos += 4;
                if (chunkLen == 0) break;
                sb.Append(isUnicode
                    ? Encoding.Unicode.GetString(ts, pos, (int)chunkLen)
                    : Encoding.Default.GetString(ts, pos, (int)chunkLen));
                pos += (int)chunkLen;
            }
            return sb.ToString();
        }

        private string _readSqlVariant(byte[] ts, ref int pos)
        {
            // sql_variant ROW value: cbMax(4) + BaseType(1) + PropBytesNum(1) + PropBytes + Value
            uint cbMax = NtlmHelper.ReadU32(ts, pos); pos += 4;
            if (cbMax == 0) return ""; // NULL

            int end = pos + (int)cbMax;
            byte baseType    = ts[pos++];
            int  propCount   = ts[pos++];
            pos += propCount; // skip type-specific metadata

            int valueLen = (int)cbMax - 2 - propCount;
            if (valueLen <= 0) { pos = end; return ""; }

            string result;
            switch (baseType)
            {
                case 0x30: // tinyint
                    result = ts[pos].ToString(); break;
                case 0x34: // smallint
                    result = ((short)(ts[pos] | (ts[pos+1] << 8))).ToString(); break;
                case 0x38: // int
                    result = ((int)(ts[pos] | (ts[pos+1]<<8) | (ts[pos+2]<<16) | (ts[pos+3]<<24))).ToString(); break;
                case 0x7F: // bigint
                {
                    long v = 0;
                    for (int i = 0; i < 8; i++) v |= ((long)ts[pos+i] << (8*i));
                    result = v.ToString(); break;
                }
                case 0x68: // bit
                    result = (ts[pos] != 0) ? "1" : "0"; break;
                case 0xE7: // nvarchar
                case 0xEF: // nchar
                    result = Encoding.Unicode.GetString(ts, pos, valueLen); break;
                case 0xA7: // varchar
                case 0xAF: // char
                    result = Encoding.Default.GetString(ts, pos, valueLen); break;
                default:
                    result = ""; break;
            }
            pos = end;
            return result;
        }

        // ── Token stream helpers ──────────────────────────────────────────────

        private byte[] _extractSspiToken(byte[] ts)
        {
            int pos = 0;
            while (pos < ts.Length)
            {
                byte tok = ts[pos++];
                if (tok == TokSspi)
                {
                    ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    byte[] data = new byte[len];
                    Buffer.BlockCopy(ts, pos, data, 0, len);
                    return data;
                }
                // Skip known tokens with simple length prefixes
                if (tok == TokEnvChange || tok == TokError || tok == TokInfo)
                {
                    ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    pos += len;
                }
                else if (tok == TokDone || tok == TokDoneProc || tok == TokDoneInProc)
                {
                    pos += 12;
                }
                else
                {
                    break; // unknown, stop scanning
                }
            }
            return null;
        }

        private bool _hasLoginAck(byte[] ts)
        {
            int pos = 0;
            while (pos < ts.Length)
            {
                byte tok = ts[pos++];
                if (tok == TokLoginAck) return true;
                if (tok == TokEnvChange || tok == TokError || tok == TokInfo)
                {
                    if (pos + 2 > ts.Length) break;
                    ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    pos += len;
                }
                else if (tok == TokDone || tok == TokDoneProc || tok == TokDoneInProc)
                {
                    pos += 12;
                }
                else if (tok == TokReturnStat)
                {
                    pos += 4;
                }
                else
                {
                    break;
                }
            }
            return false;
        }

        private string _extractErrorMessage(byte[] ts)
        {
            int pos = 0;
            while (pos < ts.Length)
            {
                byte tok = ts[pos++];
                if (tok == TokError)
                {
                    ushort tokLen = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    pos += 4 + 1 + 1; // Number + State + Class
                    ushort msgLen = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    return Encoding.Unicode.GetString(ts, pos, msgLen * 2);
                }
                if (tok == TokEnvChange || tok == TokInfo || tok == TokLoginAck)
                {
                    if (pos + 2 > ts.Length) break;
                    ushort len = NtlmHelper.ReadU16(ts, pos); pos += 2;
                    pos += len;
                }
                else if (tok == TokDone || tok == TokDoneProc || tok == TokDoneInProc)
                {
                    pos += 12;
                }
                else { break; }
            }
            return null;
        }

        // ── TDS packet I/O ────────────────────────────────────────────────────

        // Maximum bytes of payload data per TDS packet (matches the packet size negotiated
        // in LOGIN7: 4096 bytes total - 8 bytes header = 4088 bytes of data per packet).
        private const int _tdsPacketDataSize = 4088;

        private void _sendPacket(byte type, byte[] payload)
        {
            // Split into multiple TDS packets if the payload exceeds the negotiated packet
            // size. Only the final packet has the EOM (0x01) status bit set.
            int offset = 0;
            int remaining = payload.Length;

            // Always send at least one packet, even for an empty payload.
            do
            {
                int chunkLen = Math.Min(_tdsPacketDataSize, remaining);
                bool isLast  = (offset + chunkLen) >= payload.Length;
                int total    = 8 + chunkLen;

                byte[] packet = new byte[total];
                packet[0] = type;
                packet[1] = isLast ? (byte)0x01 : (byte)0x00; // EOM flag
                packet[2] = (byte)(total >> 8);
                packet[3] = (byte)(total & 0xFF);
                // SPID = 0
                packet[6] = _packetId++;
                // Window = 0
                if (chunkLen > 0)
                    Buffer.BlockCopy(payload, offset, packet, 8, chunkLen);

                _stream.Write(packet, 0, packet.Length);
                offset    += chunkLen;
                remaining -= chunkLen;
            }
            while (remaining > 0);
        }

        private byte[] _readMessage()
        {
            var data = new List<byte>();
            while (true)
            {
                byte[] hdr = _readExactly(8);
                bool eom    = (hdr[1] & 0x01) != 0;
                int pktLen  = (hdr[2] << 8) | hdr[3];
                int payLen  = pktLen - 8;
                if (payLen > 0)
                    data.AddRange(_readExactly(payLen));
                if (eom) break;
            }
            return data.ToArray();
        }

        private byte[] _readExactly(int count)
        {
            byte[] buf = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = _stream.Read(buf, read, count - read);
                if (n == 0) throw new Exception("Connection closed by SQL Server.");
                read += n;
            }
            return buf;
        }

        // ── Markdown table formatter ──────────────────────────────────────────

        private static string _toMarkdownTable(List<ColInfo> cols, List<string[]> rows)
        {
            int n = cols.Count;
            int[] widths = new int[n];
            // Use "columnN" for unnamed columns to match Print.ConvertSqlDataReaderToMarkdownTable,
            // so that Print.ExtractColumnValues(result, "column0") works correctly.
            string[] colNames = new string[n];
            for (int i = 0; i < n; i++)
            {
                colNames[i] = string.IsNullOrEmpty(cols[i].Name) ? "column" + i : cols[i].Name;
                widths[i] = colNames[i].Length;
            }

            foreach (var row in rows)
                for (int i = 0; i < n; i++)
                    if (row[i] != null && row[i].Length > widths[i])
                        widths[i] = row[i].Length;

            var sb = new StringBuilder();

            for (int i = 0; i < n; i++)
                sb.Append("| ").Append(colNames[i].PadRight(widths[i])).Append(" ");
            sb.AppendLine("|");

            for (int i = 0; i < n; i++)
                sb.Append("| ").Append(new string('-', widths[i])).Append(" ");
            sb.AppendLine("|");

            foreach (var row in rows)
            {
                for (int i = 0; i < n; i++)
                    sb.Append("| ").Append((row[i] ?? "").PadRight(widths[i])).Append(" ");
                sb.AppendLine("|");
            }

            return sb.ToString();
        }

        public void Dispose()
        {
            _stream?.Dispose();
            _tcp?.Dispose();
        }
    }
}
