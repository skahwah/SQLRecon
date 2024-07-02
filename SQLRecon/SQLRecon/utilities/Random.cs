using System;
using System.Text;

namespace SQLRecon.Utilities
{
    internal abstract class RandomStr
    {
        private static readonly Random _rand = new();

        /// <summary>
        /// The Generate method will generate a random string.
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        internal static string Generate(int length)
        {
            const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            
            StringBuilder sb = new StringBuilder();
            
            for (int i = 0; i < length; i++)
            {
                sb.Append(characters[_rand.Next(0, characters.Length)]);
            }
            
            return sb.ToString();
        }
    }
}