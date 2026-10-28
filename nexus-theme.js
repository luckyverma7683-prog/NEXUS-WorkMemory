/**
 * NEXUS Global Theme & Settings Synchronizer
 * Automatically applies themes, font size, code themes, and preferences across all NEXUS pages.
 */
(function() {
    const DEFAULT_PREFS = {
        theme: 'cyber-nexus',
        fontSize: 'standard',
        codeTheme: 'github-dark',
        streamSpeed: 'smooth',
        defaultContext: 'all'
    };

    function readStoredSettings() {
        try {
            const raw = localStorage.getItem('nexus-settings');
            if (raw) {
                const parsed = JSON.parse(raw);
                return {
                    theme: parsed.appearance?.theme || parsed.theme || localStorage.getItem('nexus-theme') || localStorage.getItem('nexusTheme') || DEFAULT_PREFS.theme,
                    fontSize: parsed.appearance?.fontSize || parsed.fontSize || DEFAULT_PREFS.fontSize,
                    codeTheme: parsed.appearance?.codeTheme || parsed.codeTheme || DEFAULT_PREFS.codeTheme,
                    streamSpeed: parsed.workspace?.streamSpeed || parsed.streamSpeed || DEFAULT_PREFS.streamSpeed,
                    defaultContext: parsed.workspace?.defaultContext || parsed.defaultContext || DEFAULT_PREFS.defaultContext,
                    ai: parsed.ai || {},
                    workspace: parsed.workspace || {},
                    appearance: parsed.appearance || {}
                };
            }
        } catch {}
        const legacyTheme = localStorage.getItem('nexus-theme') || localStorage.getItem('nexusTheme') || DEFAULT_PREFS.theme;
        return { ...DEFAULT_PREFS, theme: legacyTheme };
    }

    function applyDomSettings(prefs) {
        const root = document.documentElement;
        if (!root) return;

        // Theme
        const theme = prefs.theme || 'cyber-nexus';
        root.setAttribute('data-theme', theme);
        if (theme === 'solar-slate' || theme === 'light') {
            root.classList.add('theme-light');
            root.classList.remove('theme-dark');
        } else {
            root.classList.add('theme-dark');
            root.classList.remove('theme-light');
        }

        // Font scale
        const fontSize = prefs.fontSize || 'standard';
        root.setAttribute('data-font-size', fontSize);

        // Code block styling
        const codeTheme = prefs.codeTheme || 'github-dark';
        root.setAttribute('data-code-theme', codeTheme);

        // Stream speed
        if (prefs.streamSpeed) {
            root.setAttribute('data-stream-speed', prefs.streamSpeed);
        }
    }

    // Apply immediately to prevent FOUC
    const initial = readStoredSettings();
    applyDomSettings(initial);

    // Global helper exposed to window
    window.applyNexusSettings = function(settings, persist = true) {
        if (!settings) return;
        const appearance = settings.appearance || settings;
        const workspace = settings.workspace || settings;

        const current = readStoredSettings();
        const merged = {
            theme: appearance.theme || current.theme,
            fontSize: appearance.fontSize || current.fontSize,
            codeTheme: appearance.codeTheme || current.codeTheme,
            streamSpeed: workspace.streamSpeed || current.streamSpeed,
            defaultContext: workspace.defaultContext || current.defaultContext,
            ai: settings.ai || current.ai || {},
            workspace: settings.workspace || current.workspace || {},
            appearance: settings.appearance || current.appearance || {}
        };

        applyDomSettings(merged);

        if (persist) {
            try {
                localStorage.setItem('nexus-settings', JSON.stringify(settings));
                localStorage.setItem('nexus-theme', merged.theme);
                localStorage.setItem('nexusTheme', merged.theme);
            } catch {}
        }

        window.dispatchEvent(new CustomEvent('nexus-settings-updated', { detail: merged }));
    };

    window.getNexusSettings = function() {
        return readStoredSettings();
    };

    // Listen for storage events (realtime sync across tabs)
    window.addEventListener('storage', (e) => {
        if (e.key === 'nexus-settings' || e.key === 'nexus-theme' || e.key === 'nexusTheme') {
            const updated = readStoredSettings();
            applyDomSettings(updated);
            window.dispatchEvent(new CustomEvent('nexus-settings-updated', { detail: updated }));
        }
    });

    // Auto-sync with cloud on load if user is logged in
    document.addEventListener('DOMContentLoaded', async () => {
        applyDomSettings(readStoredSettings());

        // Connect theme toggle button if present
        const toggleBtn = document.querySelector('[data-theme-toggle]');
        if (toggleBtn) {
            const updateToggleText = () => {
                const isLight = document.documentElement.getAttribute('data-theme') === 'solar-slate'
                    || document.documentElement.getAttribute('data-theme') === 'light';
                toggleBtn.textContent = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
            };
            updateToggleText();

            toggleBtn.onclick = (e) => {
                e.preventDefault();
                const cur = document.documentElement.getAttribute('data-theme');
                const next = (cur === 'solar-slate' || cur === 'light') ? 'cyber-nexus' : 'solar-slate';
                const prefs = readStoredSettings();
                prefs.theme = next;
                if (!prefs.appearance) prefs.appearance = {};
                prefs.appearance.theme = next;
                window.applyNexusSettings(prefs, true);
                updateToggleText();
            };
        }

        // Fetch /api/settings if logged in
        try {
            const res = await fetch('/api/settings');
            if (res.ok) {
                const data = await res.json();
                if (data.settings) {
                    window.applyNexusSettings(data.settings, true);
                }
            }
        } catch {}

        // Initialize Bot Mascot interactions
        initCuteBot();
    });

    // Cute Bot Companion micro-interactions
    function initCuteBot() {
        const bots = document.querySelectorAll('.nexus-bot-mascot');
        const quotes = [
            "Beep boop! I'm NEXUS, your memory buddy! ✨",
            "Your workspace memory is encrypted & safe! 🧠",
            "Ask me anything across your files & GitHub! 🚀",
            "Looking sharp in this theme! 🎨",
            "Decisions & guidelines synced across chats! 💡",
            "Ready to supercharge your workflow! ⚡",
            "Tip: You can change themes anytime in Settings! ⚙️"
        ];
        let quoteIndex = 0;

        bots.forEach(bot => {
            const bubble = bot.querySelector('.bot-speech-bubble');
            if (!bubble) return;

            bot.addEventListener('click', () => {
                quoteIndex = (quoteIndex + 1) % quotes.length;
                bubble.textContent = quotes[quoteIndex];
                bot.classList.add('chatty');
                setTimeout(() => bot.classList.remove('chatty'), 3000);
            });
        });
    }
})();
