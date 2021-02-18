using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace DotMapFileParser
{
    static class UnDecorateStringSymbolName
    {
        static bool BetweenInAToP(char _c) => _c is >= 'A' and <= 'P';
        static readonly char[] table = { ',', '/', '\\', ':', '.', ' ', (char)0x0A, (char)0x0B, '\'', '-' };

        public static bool IsStringConstant(string name)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            bool isSingleByte = name.StartsWith("??_C@_0");
            bool isDoubleByte = name.StartsWith("??_C@_1");
            return isSingleByte || isDoubleByte;
        }

        static char? Escape(char c) => c switch
        {
            '\r' => 'r',
            '\n' => 'n',
            '\t' => 't',
            '\0' => '0',
            '\"' => '"',
            _ => null,
        };

        public static string ToHumanReadable(string name)
        {
            var sb = new StringBuilder();
            string str = UnDecorate(name, out var isUtf16);
            if (isUtf16)
                sb.Append('L');

            sb.Append('"');
            _ = str.Aggregate(sb, (sb, c) 
                => Escape(c) is char escaped ? sb.Append('\\').Append(escaped) : sb.Append(c));
            sb.Append('"');
            return sb.ToString();
        }

        public static string UnDecorate(string name, out bool isUtf16BE)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            isUtf16BE = false;
            if (!IsStringConstant(name))
            {
                return name;
            }

            isUtf16BE = name.StartsWith("??_C@_1");
            var outputString = new List<byte>(name.Length / 2);

            int curPos = "??_C@_1".Length;

            int atmarkFound = Char.IsDigit(name[curPos]) ? curPos : name.IndexOf('@', curPos); // skip encoded number.
            if (atmarkFound == -1)
                throw new FormatException();

            curPos = atmarkFound + 1;
            atmarkFound = name.IndexOf('@', curPos); // skip hash.
            if (atmarkFound >= 0)
            {
                curPos = atmarkFound + 1;
                int remains = name.Length - curPos;

                while (remains > 0)
                {
                    byte c = (byte)name[curPos];
                    ++curPos;
                    --remains;
                    if (c == '?')
                    {
                        if (remains > 2 && name[curPos] == '$' && BetweenInAToP(name[curPos + 1]) && BetweenInAToP(name[curPos + 2]))
                        {
                            byte hibit = (byte)(name[curPos + 1] - 'A');
                            byte lobit = (byte)(name[curPos + 2] - 'A');
                            c = (byte)(hibit << 4 | lobit);
                            curPos += 3;
                            remains -= 3;
                        }
                        else if (remains > 0 && name[curPos] is >= '0' and <= '9')
                        {
                            c = (byte)table[name[curPos] - '0'];
                            ++curPos;
                            --remains;
                        }
                        else if (remains > 0 && BetweenInAToP(Char.ToUpperInvariant(name[curPos]))) // 0x41-0x50 or 0x61-0x70
                        {
                            c = (byte)(name[curPos] + 0x80);
                            ++curPos;
                            --remains;
                        }
                    }
                    else if (c == '@')
                    {
                        break;
                    }

                    outputString.Add(c);

                }
                var enc = isUtf16BE ? Encoding.BigEndianUnicode : Encoding.Default;
                return enc.GetString(outputString.ToArray());
            }


            return name;
        }
    }
}
