using System;
using System.Security.Cryptography;
using System.Text;

namespace SQLRecon.Utilities
{
    internal static class NtlmHelper
    {
        private static readonly byte[] _signature = Encoding.ASCII.GetBytes("NTLMSSP\0");

        /// <summary>
        /// Parses an NT hash from "NTHASH" or "LMHASH:NTHASH" hex format into a byte array.
        /// </summary>
        internal static byte[] ParseNtHash(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("NT hash cannot be empty.");

            string[] parts = input.Split(':');
            string hex = parts[parts.Length - 1].Trim();

            if (hex.Length != 32)
                throw new ArgumentException($"NT hash must be exactly 32 hex characters, got {hex.Length}.");

            try
            {
                return HexToBytes(hex);
            }
            catch
            {
                throw new ArgumentException("NT hash contains invalid hexadecimal characters.");
            }
        }

        /// <summary>
        /// Builds an NTLM Type 1 (Negotiate) message.
        /// </summary>
        internal static byte[] BuildType1()
        {
            uint flags = 0x00000001  // NTLMSSP_NEGOTIATE_UNICODE
                       | 0x00000004  // NTLMSSP_REQUEST_TARGET
                       | 0x00000200  // NTLMSSP_NEGOTIATE_NTLM
                       | 0x00800000  // NTLMSSP_NEGOTIATE_TARGET_INFO
                       | 0x02000000  // NTLMSSP_NEGOTIATE_VERSION
                       | 0x20000000  // NTLMSSP_NEGOTIATE_128
                       | 0x80000000; // NTLMSSP_NEGOTIATE_56

            byte[] msg = new byte[40];
            Buffer.BlockCopy(_signature, 0, msg, 0, 8);
            WriteU32(msg, 8, 1);       // MessageType = 1
            WriteU32(msg, 12, flags);  // NegotiateFlags
            // DomainNameFields (8 bytes) = zeros at 16
            // WorkstationFields (8 bytes) = zeros at 24
            // Version (8 bytes): 6.1 build 7601 revision 15
            msg[32] = 6; msg[33] = 1;
            WriteU16(msg, 34, 7601);
            msg[39] = 15;
            return msg;
        }

        /// <summary>
        /// Parses an NTLM Type 2 (Challenge) message. Returns server challenge and target info.
        /// </summary>
        internal static (byte[] serverChallenge, byte[] targetInfo, uint negotiateFlags) ParseType2(byte[] type2)
        {
            for (int i = 0; i < 8; i++)
                if (type2[i] != _signature[i])
                    throw new Exception("Invalid NTLM Type 2 signature.");

            if (ReadU32(type2, 8) != 2)
                throw new Exception("Not an NTLM Type 2 message.");

            byte[] serverChallenge = new byte[8];
            Buffer.BlockCopy(type2, 24, serverChallenge, 0, 8);

            uint negotiateFlags = ReadU32(type2, 20);

            ushort targetInfoLen = ReadU16(type2, 40);
            uint targetInfoOffset = ReadU32(type2, 44);
            byte[] targetInfo = new byte[targetInfoLen];
            if (targetInfoLen > 0)
                Buffer.BlockCopy(type2, (int)targetInfoOffset, targetInfo, 0, targetInfoLen);

            return (serverChallenge, targetInfo, negotiateFlags);
        }

        /// <summary>
        /// Builds an NTLM Type 3 (Authenticate) message using NTLMv2.
        /// </summary>
        internal static byte[] BuildType3(string domain, string username, byte[] ntHash,
                                          byte[] serverChallenge, byte[] targetInfo, uint serverFlags)
        {
            byte[] domainBytes   = Encoding.Unicode.GetBytes(domain);
            byte[] userBytes     = Encoding.Unicode.GetBytes(username);
            byte[] wkstnBytes    = Encoding.Unicode.GetBytes(Environment.MachineName);

            byte[] ntlmv2Hash  = _computeNtlmv2Hash(ntHash, username, domain);
            byte[] ntResponse  = _computeNtlmv2Response(ntlmv2Hash, serverChallenge, targetInfo);

            // Keep server's negotiate flags, ensure NTLM bit is set
            uint flags = (serverFlags & 0xFFFFFFFF) | 0x00000200;

            // Fixed header: 72 bytes (no MIC)
            int lmOff   = 72;
            int ntOff   = lmOff + 24;
            int domOff  = ntOff   + ntResponse.Length;
            int userOff = domOff  + domainBytes.Length;
            int wkOff   = userOff + userBytes.Length;
            int total   = wkOff   + wkstnBytes.Length;

            byte[] msg = new byte[total];

            Buffer.BlockCopy(_signature, 0, msg, 0, 8);
            WriteU32(msg, 8, 3);  // MessageType = 3

            // LmChallengeResponseFields
            WriteU16(msg, 12, 24); WriteU16(msg, 14, 24); WriteU32(msg, 16, (uint)lmOff);
            // NtChallengeResponseFields
            WriteU16(msg, 20, (ushort)ntResponse.Length);
            WriteU16(msg, 22, (ushort)ntResponse.Length);
            WriteU32(msg, 24, (uint)ntOff);
            // DomainNameFields
            WriteU16(msg, 28, (ushort)domainBytes.Length);
            WriteU16(msg, 30, (ushort)domainBytes.Length);
            WriteU32(msg, 32, (uint)domOff);
            // UserNameFields
            WriteU16(msg, 36, (ushort)userBytes.Length);
            WriteU16(msg, 38, (ushort)userBytes.Length);
            WriteU32(msg, 40, (uint)userOff);
            // WorkstationFields
            WriteU16(msg, 44, (ushort)wkstnBytes.Length);
            WriteU16(msg, 46, (ushort)wkstnBytes.Length);
            WriteU32(msg, 48, (uint)wkOff);
            // EncryptedRandomSessionKeyFields (empty)
            WriteU32(msg, 56, (uint)total);
            // NegotiateFlags
            WriteU32(msg, 60, flags);
            // Version
            msg[64] = 6; msg[65] = 1; WriteU16(msg, 66, 7601); msg[71] = 15;

            // Payload (LM response at lmOff is already zeroed)
            Buffer.BlockCopy(ntResponse,  0, msg, ntOff,   ntResponse.Length);
            Buffer.BlockCopy(domainBytes, 0, msg, domOff,  domainBytes.Length);
            Buffer.BlockCopy(userBytes,   0, msg, userOff, userBytes.Length);
            Buffer.BlockCopy(wkstnBytes,  0, msg, wkOff,   wkstnBytes.Length);

            return msg;
        }

        private static byte[] _computeNtlmv2Hash(byte[] ntHash, string username, string domain)
        {
            byte[] identity = Encoding.Unicode.GetBytes(username.ToUpperInvariant() + domain);
            using (var hmac = new HMACMD5(ntHash))
                return hmac.ComputeHash(identity);
        }

        private static byte[] _computeNtlmv2Response(byte[] ntlmv2Hash, byte[] serverChallenge, byte[] targetInfo)
        {
            byte[] clientChallenge = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(clientChallenge);

            long ts = DateTime.UtcNow.ToFileTimeUtc();

            // Blob: RespType(1)+HiRespType(1)+Reserved(6)+Timestamp(8)+ClientChallenge(8)+Reserved(4)+TargetInfo+Reserved(4)
            int blobLen = 1 + 1 + 6 + 8 + 8 + 4 + targetInfo.Length + 4;
            byte[] blob = new byte[blobLen];
            blob[0] = 0x01; blob[1] = 0x01;
            int p = 2 + 6;
            for (int i = 0; i < 8; i++) blob[p++] = (byte)(ts >> (8 * i));
            Buffer.BlockCopy(clientChallenge, 0, blob, p, 8); p += 8;
            p += 4;
            Buffer.BlockCopy(targetInfo, 0, blob, p, targetInfo.Length);

            byte[] challengeBlob = new byte[8 + blobLen];
            Buffer.BlockCopy(serverChallenge, 0, challengeBlob, 0, 8);
            Buffer.BlockCopy(blob, 0, challengeBlob, 8, blobLen);

            byte[] ntProofStr;
            using (var hmac = new HMACMD5(ntlmv2Hash))
                ntProofStr = hmac.ComputeHash(challengeBlob);

            byte[] ntResponse = new byte[16 + blobLen];
            Buffer.BlockCopy(ntProofStr, 0, ntResponse, 0, 16);
            Buffer.BlockCopy(blob, 0, ntResponse, 16, blobLen);
            return ntResponse;
        }

        internal static byte[] HexToBytes(string hex)
        {
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        internal static void WriteU16(byte[] buf, int off, ushort val)
        {
            buf[off]   = (byte)(val & 0xFF);
            buf[off+1] = (byte)(val >> 8);
        }

        // Big-endian variant — required by TDS PreLogin option token headers
        internal static void WriteU16BE(byte[] buf, int off, ushort val)
        {
            buf[off]   = (byte)(val >> 8);
            buf[off+1] = (byte)(val & 0xFF);
        }

        internal static void WriteU32(byte[] buf, int off, uint val)
        {
            buf[off]   = (byte)(val & 0xFF);
            buf[off+1] = (byte)((val >> 8)  & 0xFF);
            buf[off+2] = (byte)((val >> 16) & 0xFF);
            buf[off+3] = (byte)(val >> 24);
        }

        internal static ushort ReadU16(byte[] buf, int off)
            => (ushort)(buf[off] | (buf[off+1] << 8));

        internal static uint ReadU32(byte[] buf, int off)
            => (uint)(buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24));
    }
}
