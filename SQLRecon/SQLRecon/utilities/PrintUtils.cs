using System;
using System.Collections.Generic;
using System.Linq;

namespace SQLRecon.Utilities
{
    internal class PrintUtils
    {
        /// <summary>
        /// The Debug method adds a debug message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string Debug(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine(string.Format("[*] DEBUG: {0}", sqlOutput));
                return "";
            }
            else
            {
                return string.Format("[*] DEBUG: {0}", sqlOutput);
            }
        }

        /// <summary>
        /// The IsOutputEmpty method checks to see if a string is empty
        /// or null before providing a generic message.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string IsOutputEmpty(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine((string.IsNullOrWhiteSpace(sqlOutput))
                    ? "[+] No results."
                    : sqlOutput);
                return "";
            }
            else
            {
                return (string.IsNullOrWhiteSpace(sqlOutput))
                    ? "[+] No results."
                    : sqlOutput;
            }
        }

        /// <summary>
        /// The Nested method adds an arrow to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string Nested(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine(string.Format(" |-> {0}", sqlOutput));
                return "";
            }
            else
            {
                return string.Format(" |-> {0}", sqlOutput);
            }
        }

        /// <summary>
        /// The Error method adds a error message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string Error(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine(string.Format("[X] ERROR: {0}", sqlOutput));
                return "";
            }
            else
            {
                return string.Format("[X] ERROR: {0}", sqlOutput);
            }
        }

        /// <summary>
        /// The Status method adds a status indicator to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string Status(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine(string.Format("[*] {0}", sqlOutput));
                return "";
            }
            else
            {
                return string.Format("[*] {0}", sqlOutput);
            }
        }

        /// <summary>
        /// The Success method adds a success message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string Success(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine(string.Format("[+] SUCCESS: {0}", sqlOutput));
                return "";
            }
            else
            {
                return string.Format("[+] SUCCESS: {0}", sqlOutput);
            }
        }

        /// <summary>
        /// The Warning method adds a warning message to the beginning
        /// of a provided string.
        /// </summary>
        /// <param name="sqlOutput"></param>
        /// <param name="print">If set to true, write the string to console,
        /// otherwise, return the modified string.</param>
        /// <returns></returns>
        public string Warning(string sqlOutput, bool print = false)
        {
            if (print == true)
            {
                Console.WriteLine(string.Format("[!] WARNING: {0}", sqlOutput));
                return "";
            }
            else
            {
                return string.Format("[!] WARNING: {0}", sqlOutput);
            }
        }
    }

    /// <summary>
    /// Modified version of https://stackoverflow.com/a/54943087
    /// </summary>
    internal class TablePrinter
    {
        private readonly string[] _titles;
        private readonly List<int> _lengths;
        private readonly List<string[]> _rows = new List<string[]>();

        public TablePrinter(params string[] titles)
        {
            this._titles = titles;
            _lengths = titles.Select(t => t.Length).ToList();
        }

        /// <summary>
        /// The AddRow method adds a row to a table.
        /// </summary>
        /// <param name="row"></param>
        public void AddRow(params object[] row)
        {
            if (row.Length != _titles.Length)
            {
                throw new System.Exception($"Added row length [{row.Length}] is not equal to title row length [{_titles.Length}]");
            }
            _rows.Add(row.Select(o => o.ToString()).ToArray());

            for (int i = 0; i < _titles.Length; i++)
            {
                if (_rows.Last()[i].Length > _lengths[i])
                {
                    _lengths[i] = _rows.Last()[i].Length;
                }
            }
        }

        /// <summary>
        /// The Print method prints all columns and rows in a table.
        /// </summary>
        public void Print()
        {
            foreach (var row in _rows)
            {
                string line = "";
                for (int i = 0; i < row.Length; i++)
                {
                    if (int.TryParse(row[i], out int n))
                    {
                        line += row[i].PadLeft(_lengths[i]) + ' ';
                    }
                    else
                    {
                        line += row[i].PadRight(_lengths[i]) + ' ';
                    }
                }
                System.Console.WriteLine(line);
            }

        }
    }
}
