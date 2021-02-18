using System;
using System.Collections.Generic;
using System.Text;

namespace DotMapFileParser
{
    [System.Serializable]
    public sealed class SymbolInfo : IEquatable<SymbolInfo>
    {
        internal SymbolInfo() { }
        public SectionInfo? SubSection { get; internal set; }
        public uint Section { get; internal init; }
        public uint Offset { get; internal init; }
        /// <summary>
        /// Rva+Base
        /// </summary>
        public ulong VirtualAddress { get; internal init; }
        public uint VirtualAddress32 { get { checked { return (uint)VirtualAddress; } } }
        public uint Size { get; internal set; }
        public string ObjectName { get; init; } = "<MUST FILL>";
        public string LibraryName => ObjectName.IndexOf(':') > -1 ? ObjectName.Split(':')[0] : "";
        public string MangledName { get; internal init; } = "<MUST FILL>";
        public string DemangledName
        {
            get
            {
                if(UnDecorateStringSymbolName.IsStringConstant(MangledName))
                {
                    return UnDecorateStringSymbolName.ToHumanReadable(MangledName);
                }
                if (MangledName.StartsWith("?") || MangledName.StartsWith("__imp_"))
                {
                    var name = MangledName;
                    bool importThunk = name.StartsWith("__imp_");
                    if (importThunk)
                    {
                        name = name.Substring("__imp_".Length);
                    }

                    var buf = new StringBuilder(1024);
                    buf.Length = Dbghelp.UnDecorateSymbolName(name, buf, buf.Capacity, UnDecorateFlags.UNDNAME_COMPLETE);
                    if (buf.Length == 0)
                        throw new System.ComponentModel.Win32Exception();

                    if (importThunk)
                        _ = buf.Insert(0, "<import>");

                    return buf.ToString();
                }
                else
                    return MangledName;
            }
        }

        public bool Function { get; internal init; }
        public bool Inline { get; internal init; }

        public override string ToString()
        {
            return $"Section = {Section:X4}, Address = {Offset:X8}, DemangledName = \"{DemangledName}\", VirtualAddress = {VirtualAddress:X8}, ObjectName = \"{ObjectName}\"";
        }

        public string ToSimpleString()
        {
            return $"{Section:X4}:{Offset:X8} {DemangledName} {VirtualAddress:X8} {ObjectName}";
        }

        public bool Equals(SymbolInfo? other)
        {
            return other is not null &&
                Section == other.Section &&
                Offset == other.Offset &&
                MangledName == other.MangledName;
        }

        public override int GetHashCode()
        {
            int hashCode = 1730111542;
            hashCode = hashCode * -1521134295 + Section.GetHashCode();
            hashCode = hashCode * -1521134295 + Offset.GetHashCode();
            hashCode = hashCode * -1521134295 + MangledName.GetHashCode();
            return hashCode;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as SymbolInfo);
        }
    }
}
