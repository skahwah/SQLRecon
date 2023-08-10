using System.Collections.Generic;
using SQLRecon.Modules;

namespace SQLRecon.Utilities
{
    internal class SetEnumerationType
    {
        /// <summary>
        /// The EvaluateEnumerationType method is responsible for determining
        /// what enumeration module to use.
        /// </summary>
        /// <param name="argumentDictionary">User supplied command line arguments.</param>
        public static void EvaluateEnumerationType(Dictionary<string, string> argumentDictionary)
        {
            if (argumentDictionary["enum"].ToLower().Equals("sqlspns"))
            {
               _sqlSpns(argumentDictionary);
            }
            else
            {
                //Go no further
                return;
            }
        }

        /// <summary>
        /// The _sqlSpns method will enumerate AD for SPN objects associated with MSSQL.
        /// If the '/d, /domain:' flag is not specified, the current domain is used.
        /// </summary>
        /// <param name="argumentDictionary"></param>
        /// <returns></returns>
        private static void _sqlSpns(Dictionary<string, string> argumentDictionary)
        {
            string domain = "";

            if (argumentDictionary.ContainsKey("domain"))
            {
                domain = argumentDictionary["domain"];
            }

            DomainSPNs.GetMSSQLSPNs(domain);
        }
    }
}
