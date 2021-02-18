using System;
using System.Collections.Generic;
using System.Linq;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("MapFileParserTest")]

namespace DotMapFileParser
{
    [System.Serializable]
    public record MapFileInfo(
        uint RawTimeStamp,
        ulong PreferredLoadAddress,
        bool Is64Bit,
        string ModuleName,
        IReadOnlyList<SectionInfo> SubSections,
        IReadOnlyList<SymbolInfo> Symbols,
        IReadOnlyList<SymbolInfo> StaticSymbols)
    {
        static readonly DateTime _Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public DateTime TimeStamp => _Epoch.AddSeconds(RawTimeStamp);
        public ILookup<uint, SectionInfo> Sections => SubSections.ToLookup(section => section.Section);

        public void FixupRecordSize()
        {
            Symbols.ForEach((s, i) =>
            {
                if (Sections.Contains(s.Section))
                {

                }
            });
            for (var i = 0; i < Symbols.Count; i++)
            {
            }
        }
    }
}