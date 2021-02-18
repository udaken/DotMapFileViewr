using System;
using System.Globalization;

namespace DotMapFileViewer
{
    [System.Windows.Data.ValueConversion(typeof(bool), typeof(string))]
    class BooleanToCheckMarkConverter : System.Windows.Data.IValueConverter
    {
        public static BooleanToCheckMarkConverter Instance { get; } = new BooleanToCheckMarkConverter();
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (bool)value ? "✔" : "";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
