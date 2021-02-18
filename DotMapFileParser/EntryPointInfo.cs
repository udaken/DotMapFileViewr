[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("MapFileParserTest")]

namespace DotMapFileParser
{
    [System.Serializable]
    public sealed record EntryPointInfo(uint Section, uint SectionStart)
    {
        public override string ToString() => $"{Section:X4}:{SectionStart:X8}";
    }
}