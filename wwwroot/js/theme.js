window.theme = {
    LIGHT: 'light',
    DARK: 'dark',
    STORAGE_KEY: 'certrobo-theme-preference',

    /**
     * Initialize theme based on user preference or OS setting
     * @returns {string} The current theme ('light' or 'dark')
     */
    initialize: function() {
        const savedTheme = localStorage.getItem(this.STORAGE_KEY);
        
        let theme;
        if (savedTheme) {
            // Use saved preference
            theme = savedTheme;
        } else {
            // Detect OS preference
            theme = this.getOSPreference();
            // Don't save on first load, let user choose
        }

        this.applyTheme(theme);
        return theme;
    },

    /**
     * Get the user's OS color scheme preference
     * @returns {string} 'dark' or 'light'
     */
    getOSPreference: function() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return this.DARK;
        }
        return this.LIGHT;
    },

    /**
     * Toggle between light and dark themes
     * @returns {string} The new theme
     */
    toggle: function() {
        const root = document.documentElement;
        const currentTheme = root.getAttribute('data-theme') || this.LIGHT;
        const newTheme = currentTheme === this.LIGHT ? this.DARK : this.LIGHT;
        
        this.setTheme(newTheme);
        return newTheme;
    },

    /**
     * Set a specific theme
     * @param {string} theme - 'light' or 'dark'
     * @returns {string} The theme that was set
     */
    set: function(theme) {
        if (theme === this.LIGHT || theme === this.DARK) {
            this.setTheme(theme);
        }
        return theme;
    },

    /**
     * Apply theme to DOM and save preference
     * @param {string} theme - 'light' or 'dark'
     */
    setTheme: function(theme) {
        const root = document.documentElement;
        root.setAttribute('data-theme', theme);
        localStorage.setItem(this.STORAGE_KEY, theme);
        this.updateMetaThemeColor(theme);
    },

    /**
     * Apply theme styles
     * @param {string} theme - 'light' or 'dark'
     */
    applyTheme: function(theme) {
        const root = document.documentElement;
        root.setAttribute('data-theme', theme);
        this.updateMetaThemeColor(theme);
    },

    /**
     * Update the meta theme-color tag for browser UI
     * @param {string} theme - 'light' or 'dark'
     */
    updateMetaThemeColor: function(theme) {
        let metaThemeColor = document.querySelector('meta[name="theme-color"]');
        if (!metaThemeColor) {
            metaThemeColor = document.createElement('meta');
            metaThemeColor.name = 'theme-color';
            document.head.appendChild(metaThemeColor);
        }
        metaThemeColor.content = theme === this.DARK ? '#1a1a1a' : '#ffffff';
    },

    /**
     * Watch for OS theme changes
     */
    watchOSPreference: function() {
        if (!window.matchMedia) return;

        const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
        darkModeQuery.addEventListener('change', (e) => {
            const savedTheme = localStorage.getItem(this.STORAGE_KEY);
            // Only apply OS preference if user hasn't manually set a preference
            if (!savedTheme) {
                this.applyTheme(e.matches ? this.DARK : this.LIGHT);
            }
        });
    }
};

// Initialize theme on script load
document.addEventListener('DOMContentLoaded', function() {
    window.theme.initialize();
    window.theme.watchOSPreference();
});