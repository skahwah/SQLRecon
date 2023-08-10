using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;

namespace SQLRecon.Utilities
{
    internal sealed class Ldap
    {
        private readonly DomainSearcher _searcher;
        
        public Ldap(DomainSearcher searcher)
        {
            _searcher = searcher;
        }
        
        /// <summary>
        /// The ExecuteQuery method allows LDAP queries to be executed 
        /// against a domain controller.
        /// </summary>
        /// <param name="filter"></param>
        /// <param name="properties"></param>
        /// <returns></returns>
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