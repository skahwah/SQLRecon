using System;
using System.Text;

namespace SQLRecon.Utilities
{
    internal class RandomString
    {
        private readonly Random _rand = new();

        /// <summary>
        /// The Generate method will generate a random string.
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public string Generate(int length)
        {
            const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            var sb = new StringBuilder();
            
            for (var i = 0; i < length; i++)
            {
                sb.Append(characters[_rand.Next(0, characters.Length)]);
            }
            return sb.ToString();
        }
    }
}