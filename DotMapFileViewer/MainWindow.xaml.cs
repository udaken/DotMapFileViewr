using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace DotMapFileViewer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        MapFileInfoViewModel _mapFileInfo;
        public MainWindow()
        {
            InitializeComponent();
            var args = Environment.GetCommandLineArgs();
            if (args.Length > 1)
                LoadFromPath(args[1]);
        }

        private void LoadFromPath(string filepath)
        {
            using var stream = File.OpenRead(filepath);
            _mapFileInfo = new MapFileInfoViewModel(DotMapFileParser.MapFileParser.Parse(stream)) { FilePath = filepath };
            DataContext = _mapFileInfo;
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            var obj = (string[])e.Data.GetData(DataFormats.FileDrop);
            LoadFromPath(obj[0]);
            e.Handled = true;
        }

        private void Window_PreviewDragOver(object sender, DragEventArgs e)
        {
            var obj = (string[])e.Data.GetData(DataFormats.FileDrop);
            e.Effects = obj.Length == 1 ? DragDropEffects.Copy : DragDropEffects.None;
            e.Handled = true;
        }
    }
}
