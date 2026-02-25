using Microsoft.JSInterop;

namespace CertRobo.Shared
{
    public class ThemeService
    {
        private readonly IJSRuntime _jsRuntime;
        private string _currentTheme = "light";

        public string CurrentTheme => _currentTheme;

        public event Action? OnThemeChanged;

        public ThemeService(IJSRuntime jsRuntime)
        {
            _jsRuntime = jsRuntime;
        }

        public async Task InitializeThemeAsync()
        {
            try
            {
                _currentTheme = await _jsRuntime.InvokeAsync<string>("theme.initialize");
                NotifyThemeChanged();
            }
            catch (JSException ex)
            {
                Console.WriteLine($"Error initializing theme: {ex.Message}");
            }
        }

        public async Task ToggleThemeAsync()
        {
            try
            {
                _currentTheme = await _jsRuntime.InvokeAsync<string>("theme.toggle");
                NotifyThemeChanged();
            }
            catch (JSException ex)
            {
                Console.WriteLine($"Error toggling theme: {ex.Message}");
            }
        }

        public async Task SetThemeAsync(string theme)
        {
            if (theme != "light" && theme != "dark")
                return;

            try
            {
                _currentTheme = await _jsRuntime.InvokeAsync<string>("theme.set", theme);
                NotifyThemeChanged();
            }
            catch (JSException ex)
            {
                Console.WriteLine($"Error setting theme: {ex.Message}");
            }
        }

        private void NotifyThemeChanged()
        {
            OnThemeChanged?.Invoke();
        }
    }
}
