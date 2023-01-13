using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;

namespace SQLRecon.utilities
{
    public sealed class Ldap
    {
        private readonly DomainSearcher _searcher;
        
        public Ldap(DomainSearcher searcher)
        {
            _searcher = searcher;
        }
        
        public Dictionary<string, Dictionary<string, object[]>> ExecuteQuery(string filter, string[] properties = null)
        {
            var searcher = new DirectorySearcher(_searcher.Directory)
            {
                Filter = filter,
            };

            if (properties is not null)
            {
                searcher.PropertiesToLoad.AddRange(properties);
            }

            var searchResultCollection = searcher.FindAll();

            var resultDictionary = new Dictionary<string, Dictionary<string, object[]>>();

            foreach (SearchResult searchResult in searchResultCollection)
            {
                resultDictionary.Add(searchResult.Path, null);

                var dictionary = new Dictionary<string, object[]>();

                foreach (DictionaryEntry entry in searchResult.Properties)
                {
                    var values = new List<object>();

                    foreach (var value in (ResultPropertyValueCollection)entry.Value)
                        values.Add(value);

                    dictionary.Add(entry.Key.ToString(), values.ToArray());
                }

                resultDictionary[searchResult.Path] = dictionary;
            }

            return resultDictionary;
        }
    }
}