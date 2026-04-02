using System.Data.SqlClient;
using System.Runtime.CompilerServices;

namespace SQLRecon.Utilities
{
    /// <summary>
    /// Holds the active PTHTdsConnection and maps dummy SqlConnection sentinels
    /// to their underlying PTHTdsConnection instances.
    /// Kept in the Utilities namespace to avoid a circular dependency with SQLRecon.Commands.
    /// </summary>
    internal static class PthState
    {
        internal static PTHTdsConnection Connection { get; set; }

        // Maps dummy SqlConnection sentinels to their PTHTdsConnection.
        // ConditionalWeakTable uses reference equality for keys and does not prevent
        // keys from being GC'd, so entries clean up automatically.
        private static readonly ConditionalWeakTable<SqlConnection, PTHTdsConnection> _map
            = new ConditionalWeakTable<SqlConnection, PTHTdsConnection>();

        /// <summary>
        /// Creates a new dummy SqlConnection sentinel associated with the given
        /// PTHTdsConnection. Pass the returned sentinel as the SqlConnection
        /// parameter to Sql.Query/CustomQuery/NonQuery.
        /// </summary>
        internal static SqlConnection Wrap(PTHTdsConnection pthConn)
        {
            SqlConnection sentinel = new SqlConnection();
            _map.Add(sentinel, pthConn);
            return sentinel;
        }

        /// <summary>
        /// Returns the PTHTdsConnection associated with the given SqlConnection,
        /// or null if it is not a PTH sentinel.
        /// </summary>
        internal static PTHTdsConnection Unwrap(SqlConnection con)
        {
            if (con == null) return null;
            _map.TryGetValue(con, out PTHTdsConnection pthConn);
            return pthConn;
        }
    }
}
