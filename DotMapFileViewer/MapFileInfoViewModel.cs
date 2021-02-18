using DotMapFileParser;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

#nullable enable

namespace DotMapFileViewer
{
    class MapFileInfoViewModel : INotifyPropertyChanged
    {
        readonly MapFileInfo? _MapFileInfo;
        private ulong? _PreferredLoadAddress;
        private bool _Demangled = false;

        public MapFileInfoViewModel()
        {
            Sections = Array.Empty<SectionInfo>();
            Symbols = Array.Empty<SymbolInfoVM>();
            StaticSymbols = Array.Empty<SymbolInfoVM>();
        }
        public MapFileInfoViewModel(MapFileInfo mapFileInfo)
        {
            _MapFileInfo = mapFileInfo ?? throw new ArgumentNullException(nameof(mapFileInfo));

            _PreferredLoadAddress = _MapFileInfo.PreferredLoadAddress;
            Sections = _MapFileInfo.SubSections;
            Symbols = _MapFileInfo.Symbols.Select(s => new SymbolInfoVM(this, s)).ToList();
            StaticSymbols = _MapFileInfo.StaticSymbols.Select(s => new SymbolInfoVM(this, s)).ToList();
        }

        public string FilePath { get; init; } = "";

        public bool Demangled
        {
            get => _Demangled;
            set
            {
                if(_Demangled != value)
                {
                    _Demangled = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Demangled)));
                }
            }
        }
        public DateTime? TimeStamp => _MapFileInfo?.TimeStamp;
        internal ulong OriginalPreferredLoadAddress => _MapFileInfo?.PreferredLoadAddress ?? 0;
        public ulong? PreferredLoadAddress
        {
            get => _PreferredLoadAddress;
            set
            {
                if (_PreferredLoadAddress != value)
                {
                    _PreferredLoadAddress = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(PreferredLoadAddress)));
                }
            }
        }
        public bool? Is64Bit => _MapFileInfo?.Is64Bit;
        public string ModuleName => _MapFileInfo?.ModuleName ?? "";
        public IReadOnlyList<SectionInfo> Sections { get; }
        public IReadOnlyList<SymbolInfoVM> Symbols { get; }

        public IReadOnlyList<SymbolInfoVM> StaticSymbols { get; }

        public event PropertyChangedEventHandler? PropertyChanged;
    }

    class SymbolInfoVM : INotifyPropertyChanged
    {
        private readonly MapFileInfoViewModel _MapFile;
        private readonly SymbolInfo _SymbolInfo;

        public SymbolInfoVM(MapFileInfoViewModel mapFile, SymbolInfo symbolInfo)
        {
            _MapFile = mapFile ?? throw new ArgumentNullException(nameof(mapFile));
            _SymbolInfo = symbolInfo ?? throw new ArgumentNullException(nameof(symbolInfo));
            Rva = symbolInfo.VirtualAddress - _MapFile.OriginalPreferredLoadAddress;
            mapFile.PropertyChanged += MapFile_PropertyChanged;
        }

        private void MapFile_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(_MapFile.PreferredLoadAddress))
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(VirtualAddress)));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;


        public SectionInfo? SubSection => _SymbolInfo.SubSection;
        public uint Section => _SymbolInfo.Section;
        public uint Offset => _SymbolInfo.Offset;

        private ulong Rva { get; }

        public ulong VirtualAddress => Rva + _MapFile.PreferredLoadAddress ?? 0;

        public uint Size => _SymbolInfo.Size;
        public string ObjectName => _SymbolInfo.ObjectName;
        public string LibraryName => _SymbolInfo.LibraryName;
        public string MangledName => _SymbolInfo.MangledName;
        public string DemangledName => _SymbolInfo.DemangledName;

        public bool Function => _SymbolInfo.Function;
        public bool Inline => _SymbolInfo.Inline;

    }
}
