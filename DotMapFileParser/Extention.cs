using System;
using System.Collections.Generic;
using System.IO;

namespace DotMapFileParser
{
    internal static class Extention
    {
        public enum ForEachBehiver
        {
            Continue,
            Break,
        }
        public static void ForEach<T>(this IEnumerable<T> source, Action<T, int> action)
        {
            int i = 0;
            foreach (var elem in source)
            {
                action(elem, i++);
            }
        }
        public static void ForEach<T>(this IEnumerable<T> source, Func<T, int, ForEachBehiver> action)
        {
            int i = 0;
            foreach (var elem in source)
            {
                var ret = action(elem, i++);
                if (ret == ForEachBehiver.Break)
                    break;
            }
        }

        public static string RemoveHeader(this string str, string value) 
            => str.StartsWith(value) ? str.Substring(value.Length) : str;
    }

    internal static class TextReaderExtention
    {
        public static IList<string> ReadAllLines(this StreamReader reader)
        {
            var list = new List<string>();
            while (true)
            {
                var line = reader.ReadLine();
                if (line == null)
                    break;
                list.Add(line);
            }
            return list;
        }
    }

}
