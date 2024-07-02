using System.DirectoryServices;

namespace SQLRecon.Utilities
{
    internal sealed class DomainSearcher
    {
        internal DirectoryEntry Directory { get; }
        
        internal DomainSearcher()
        {
            Directory = new DirectoryEntry();
        }
        
        internal DomainSearcher(string path)
        {
            Directory = new DirectoryEntry(path);
        }
    }
}