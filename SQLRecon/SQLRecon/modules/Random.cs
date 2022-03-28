using System;
using System.Text;

namespace SQLRecon.Modules
{
    public class RandomString
    {
        Random rand = new Random();

        public string Generate(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            var sb = new StringBuilder();
            
            for (var i = 0; i<length; i++)
            {
                var c = chars[rand.Next(0, chars.Length)];
                sb.Append(c);
            }
            return sb.ToString();
        }
    }
}