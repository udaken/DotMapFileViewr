using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;
using System.Text.RegularExpressions;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("MapFileParserTest")]

namespace DotMapFileParser
{
    public static class MapFileParser
    {
        private static void SkipWhileEmptyLine(TextReader reader, out string line)
        {
            do
            {
                line = reader.ReadLine();
                if (line == null)
                    break;
            } while (line == "");
        }

        public static MapFileInfo Parse(Stream stream) => Parse(stream, Encoding.Default);

        public static MapFileInfo Parse(Stream stream, Encoding encoding)
        {
            using var reader = new StreamReader(stream, encoding);
            return Parse(reader);
        }

        public static MapFileInfo Parse(string content)
        {
            var reader = new StringReader(content);
            return Parse(reader);
        }

        public static MapFileInfo Parse(TextReader reader)
        {
            var moduleName = reader.ReadLine().Trim();

            SkipWhileEmptyLine(reader, out string line);

            const string timeStampText = " Timestamp is ";
            //  Timestamp is 5930b2e8 (Fri Jun 02 09:35:52 2017)
            if (!line.StartsWith(timeStampText))
                throw new MapFileFormatException();
            var timeStamp = line.Substring(timeStampText.Length, 8);

            SkipWhileEmptyLine(reader, out line);

            //  Preferred load address is 00010000
            var PreferredLoadAddress = line.Trim().Split(' ').Last();

            SkipWhileEmptyLine(reader, out line);
            if (!line.StartsWith(" Start "))
                throw new MapFileFormatException();

            SkipWhileEmptyLine(reader, out line);

            var sections = new List<string>();
            do
            {
                if (string.IsNullOrEmpty(line))
                    break;
                sections.Add(line);
                line = reader.ReadLine();
            } while (true);

            SkipWhileEmptyLine(reader, out line);
            //   Address         Publics by Value              Rva+Base       Lib:Object
            if (!line.StartsWith("  Address "))
                throw new MapFileFormatException();

            SkipWhileEmptyLine(reader, out line);

            var symbols = new List<string>();
            do
            {
                if (string.IsNullOrEmpty(line))
                    break;
                symbols.Add(line);
                line = reader.ReadLine();
            } while (true);

            SkipWhileEmptyLine(reader, out line);
            const string entryPointAtText = " entry point at ";
            //  entry point at        0001:0007ddc4
            if (!line.StartsWith(entryPointAtText))
                throw new MapFileFormatException();

            var entryPointAt = line.RemoveHeader(entryPointAtText).Trim();


            SkipWhileEmptyLine(reader, out line);
            //  Static symbols
            if (!line.StartsWith(" Static symbols"))
                throw new MapFileFormatException();

            SkipWhileEmptyLine(reader, out line);

            var staticSymbols = new List<string>();
            do
            {
                if (string.IsNullOrEmpty(line))
                    break;
                staticSymbols.Add(line);
                line = reader.ReadLine();
            } while (true);

            return ParseCore(moduleName, timeStamp, PreferredLoadAddress, sections, symbols, staticSymbols);
        }

        static (string rvaBase, bool f, bool i, string objectName) SplitRvaBaseAndObjName(string rvaBaseAndObjName)
        {
            var f = false;
            var i = false;
            var array = rvaBaseAndObjName.Split(new[] { ' ' }, 2);
            var rvaBase = array[0];
            var x = array[1];
            if (x[0] == 'f')
            {
                f = true;
            }
            if (x[2] == 'i')
            {
                i = true;
            }
            var objectName = x.Substring(4);

            return (rvaBase, f, i, objectName);
        }

        private static SymbolInfo ToRecord(string symbol)
        {
            var text = symbol.Split(new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);

            string rvaBaseAndObjName = text[2];
            var (rvaBase, f, i, objectName) = SplitRvaBaseAndObjName(rvaBaseAndObjName);
            var info = new SymbolInfo()
            {
                Section = uint.Parse(text[0].Split(':')[0], NumberStyles.HexNumber),
                Offset = uint.Parse(text[0].Split(':')[1], NumberStyles.HexNumber),
                MangledName = text[1],
                VirtualAddress = ulong.Parse(rvaBase, NumberStyles.HexNumber),
                ObjectName = objectName,
                Function = f,
                Inline = i,
            };
            return info;
        }

        private static void FixupRecordSize(IReadOnlyList<SectionInfo> subSections, IReadOnlyList<SymbolInfo> symbolList)
        {
            for (var i = 0; i < symbolList.Count; i++)
            {
                var symbol = symbolList[i];
                var section = subSections.SingleOrDefault(subsection => subsection.Section == symbol.Section && subsection.SectionStart <= symbol.Offset && symbol.Offset < subsection.SectionStart + subsection.Length);
                if (section != default)
                {
                    symbol.Size = symbol.ObjectName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                        ? 0x10
                        : i + 1 < symbolList.Count && symbolList[i + 1].Section == symbol.Section
                            ? symbolList[i + 1].Offset - symbol.Offset
                            : (section.SectionStart + section.Length) - symbol.Offset;
                    symbol.SubSection = section;
                }
            }
        }

        private static MapFileInfo ParseCore(string moduleName, string timeStampText, string PreferredLoadAddress, IList<string> subSections, IList<string> symbols, IList<string> staticSymbols)
        {
            var timeStamp = uint.Parse(timeStampText, NumberStyles.HexNumber);
            var is64bit = true;

            if (PreferredLoadAddress.Length == 8)
            {
                is64bit = false;
            }
            else
            {
                System.Diagnostics.Debug.Assert(PreferredLoadAddress.Length == 16);
                is64bit = true;
            }

            var sectionList = subSections
                .Select(sectionText =>
                {
                    var text = sectionText.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                var info = new SectionInfo(
                        Section: uint.Parse(text[0].Split(':')[0], NumberStyles.HexNumber),
                        SectionStart: uint.Parse(text[0].Split(':')[1], NumberStyles.HexNumber),
                        Length: uint.Parse(text[1].TrimEnd('H'), NumberStyles.HexNumber),
                        Name: text[2],
                        Class: text[3] == "CODE" ? SectionClass.Code :
                                text[3] == "DATA" ? SectionClass.Data :
                                SectionClass.None
                    );
                    return info;
                })
                .OrderBy(subSection => Tuple.Create(subSection.Section, subSection.SectionStart))
                .ToList();

            var symbolList = symbols
                .Select(symbol => ToRecord(symbol))
                .ToList();

            var staticSymbolList = staticSymbols
                .Select(symbol => ToRecord(symbol))
                .OrderBy(symbol => Tuple.Create(symbol.Section, symbol.Offset))
                .ToList();

            FixupRecordSize(sectionList, symbolList);
            FixupRecordSize(sectionList, staticSymbolList);

            return new MapFileInfo(
                RawTimeStamp: timeStamp,
                ModuleName: moduleName,
                SubSections: sectionList.AsReadOnly(),
                Symbols: symbolList.AsReadOnly(),
                StaticSymbols: staticSymbolList.AsReadOnly(),
                PreferredLoadAddress: ulong.Parse(PreferredLoadAddress, NumberStyles.HexNumber),
                Is64Bit: is64bit);
        }
    }
}