[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("MapFileParserTest")]

namespace DotMapFileParser
{
    [System.Serializable]
    public sealed record SectionInfo(
        uint Section,
        uint SectionStart,
        uint Length,
        string Name,
        SectionClass Class)
    {
        public override string ToString() => $"{Section:X4}:{SectionStart:X8} {Length:X8} {Name} {Class}";
    }
}