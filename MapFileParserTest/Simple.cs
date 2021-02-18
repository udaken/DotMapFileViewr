using DotMapFileParser;
using System;
using System.IO;
using Xunit;

namespace test
{
    public class Simple
    {
        const string _text = @" Simple

 Timestamp is 601a0342 (Wed Feb  3 10:58:26 2021)

 Preferred load address is 40000000

 Start         Length     Name                   Class
 0001:00000000 00011b50H .text$mn                CODE

  Address         Publics by Value              Rva+Base               Lib:Object

 0001:000012b0       wWinMain                   400022b0 f i FileProtocolHandler.obj

 entry point at        0001:0000333c

 Static symbols

 0000:fffc3000       .debug$S                   40000000     kernel32:KERNEL32.dll
";

        [Fact]
        public void Test()
        {
            var info = DotMapFileParser.MapFileParser.Parse(_text);
            Assert.Equal(new DateTime(2021, 2, 3, 10, 58, 26), info.TimeStamp.ToLocalTime());
            Assert.False(info.Is64Bit);
            Assert.Equal(0x00000001UL, info.PreferredLoadAddress);
            Assert.Equal(1, info.SubSections.Count);
            Assert.Equal(new SectionInfo(
                Section: 1,
                SectionStart: 0x00000000u,
                Length: 0x00011b50,
                Name: ".text$mn",
                Class: SectionClass.Code
            ) , info.SubSections[0]);
            Assert.Equal(1, info.Symbols.Count);
            {
                var symbol = info.Symbols[0];
                Assert.Equal(0x0001U, symbol.Section);
                Assert.Equal(0x000012b0U, symbol.Offset);
                Assert.Equal("wWinMain", symbol.MangledName);
                Assert.Equal(0x00000001400022b0UL, symbol.VirtualAddress);
                Assert.True(symbol.Inline);
                Assert.True(symbol.Function);
                Assert.Equal("FileProtocolHandler.obj", symbol.ObjectName);
            }
            Assert.Equal(1, info.StaticSymbols.Count);
            {
                var symbol = info.StaticSymbols[0];
                Assert.Equal(0x0000U, symbol.Section);
                Assert.Equal(0xfffc3000, symbol.Offset);
                Assert.Equal(".debug$S", symbol.MangledName);
                Assert.Equal(0x0000000140000000UL, symbol.VirtualAddress);
                Assert.False(symbol.Inline);
                Assert.False(symbol.Function);
                Assert.Equal("kernel32:KERNEL32.dll", symbol.ObjectName);
            }
        }
    }
}
