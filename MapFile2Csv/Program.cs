using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DotMapFileParser;
using CsvHelper;
using CsvHelper.Configuration;
using System.Text;
using System.Globalization;

namespace MapFile2Csv
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            using var input = File.OpenRead(args[0]);
            var mapfileinfo = MapFileParser.Parse(input);

            using (var writer = new StreamWriter(args[0] + ".sections.csv", append: false, Encoding.UTF8))
            {
                OutputSections(writer, mapfileinfo.SubSections);
            }
            using (var writer = new StreamWriter(args[0] + ".symbols.csv", append: false, Encoding.UTF8))
            {
                OutputSymbols(writer, mapfileinfo.Symbols);
            }
            using (var writer = new StreamWriter(args[0] + ".staticsymbols.csv", append: false, Encoding.UTF8))
            {
                OutputSymbols(writer, mapfileinfo.StaticSymbols);
            }
        }

        static readonly CsvConfiguration Configuration = new CsvConfiguration(CultureInfo.CurrentCulture)
        {
            HasHeaderRecord = true,
            ShouldQuote = (field, context, row) => true,
        };

        class SectionInfoMapper : ClassMap<SectionInfo>
        {
            public SectionInfoMapper()
            {
                var index = 0;
                _ = Map(record => record.Section).Index(index++).Name(nameof(SectionInfo.Section)).TypeConverter<HexValueTypeConverter>();
                _ = Map(record => record.SectionStart).Index(index++).Name(nameof(SectionInfo.SectionStart)).TypeConverter<HexValueTypeConverter>();
                _ = Map(record => record.Length).Index(index++).Name(nameof(SectionInfo.Length));
                _ = Map(record => record.Name).Index(index++).Name(nameof(SectionInfo.Name));
                _ = Map(record => record.Class).Index(index++).Name(nameof(SectionInfo.Class));
            }
        }

        static void OutputSections(TextWriter writer, IEnumerable<SectionInfo> sections)
        {
            using var csvWriter = new CsvHelper.CsvWriter(writer, Configuration);

            csvWriter.Context.RegisterClassMap(new SectionInfoMapper());
            csvWriter.WriteRecords(sections);
        }

        class HexValueTypeConverter : CsvHelper.TypeConversion.ITypeConverter
        {
            public object ConvertFromString(string text, IReaderRow row, MemberMapData memberMapData) => throw new NotImplementedException();

            public string ConvertToString(object value, IWriterRow row, MemberMapData memberMapData)
                => value switch
                {
                    uint v => $"0x{v:X8}",
                    ulong v => $"0x{v:X8}",
                    null => "",
                    _ => value.ToString(),
                };
        }
        class SymbolInfoMapper : ClassMap<SymbolInfo>
        {
            public SymbolInfoMapper()
            {
                var index = 0;
                _ = Map(record => record.Section).Index(index++).Name(nameof(SymbolInfo.Section)).TypeConverter<HexValueTypeConverter>();
                _ = Map(record => record.Offset).Index(index++).Name(nameof(SymbolInfo.Offset)).TypeConverter<HexValueTypeConverter>();
                _ = Map(record => record.Size).Index(index++).Name(nameof(SymbolInfo.Size));
                _ = Map(record => record.MangledName).Index(index++).Name(nameof(SymbolInfo.MangledName));
                _ = Map(record => record.DemangledName).Index(index++).Name(nameof(SymbolInfo.DemangledName));
                _ = Map(record => record.Function).Index(index++).Name(nameof(SymbolInfo.Function));
                _ = Map(record => record.Inline).Index(index++).Name(nameof(SymbolInfo.Inline));
                _ = Map(record => record.VirtualAddress).Index(index++).Name(nameof(SymbolInfo.VirtualAddress)).TypeConverter<HexValueTypeConverter>();
                _ = Map(record => record.ObjectName).Index(index++).Name(nameof(SymbolInfo.ObjectName));
            }
        }

        static void OutputSymbols(TextWriter writer, IEnumerable<SymbolInfo> symbols)
        {
            using var csvWriter = new CsvHelper.CsvWriter(writer, Configuration);

            csvWriter.Context.RegisterClassMap(new SymbolInfoMapper());
            csvWriter.WriteRecords(symbols);
        }
    }
}
