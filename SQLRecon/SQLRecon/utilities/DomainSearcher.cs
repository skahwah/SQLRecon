using System.DirectoryServices;

namespace SQLRecon.Utilities
{
    internal sealed class DomainSearcher
    {
        public DirectoryEntry Directory { get; }
        
        public DomainSearcher()
        {
            Directory = new DirectoryEntry();
        }
        
        public DomainSearcher(string path)
        {
            Directory = new DirectoryEntry(path);
        }
        
        public DomainSearcher(string path, string username, string password)
        {
            Directory = new DirectoryEntry(path, username, password);
        }
    }
}