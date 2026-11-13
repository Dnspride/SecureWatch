/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: {
          DEFAULT: "#f4f6f8",
          dark: "#0b0f19",
        },
        surface: {
          50: "#ffffff",
          100: "#f8fafc",
          200: "#f1f5f9",
          300: "#e2e8f0",
          700: "#1e293b",
          800: "#131b2e",
          900: "#0f172a",
          950: "#080c14",
        },
        brand: {
          50: "#eff6ff",
          100: "#dbeafe",
          200: "#bfdbfe",
          300: "#93c5fd",
          400: "#60a5fa",
          500: "#0078d4", // Microsoft Defender Blue
          600: "#006cbd",
          700: "#005a9e",
          800: "#106ebe",
          900: "#004578",
        },
        cyan: {
          400: "#0078d4",
          500: "#0078d4",
          600: "#006cbd",
        },
      },
      fontFamily: {
        sans: [
          "'Segoe UI'",
          "'Plus Jakarta Sans'",
          "-apple-system",
          "BlinkMacSystemFont",
          "Roboto",
          "sans-serif",
        ],
        mono: ["'JetBrains Mono'", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)",
        elevated: "0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.05)",
        defender: "0 2px 4px rgba(0,0,0,0.06), 0 0 1px rgba(0,0,0,0.12)",
        "dark-card": "0 1px 3px 0 rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.05)",
        "dark-glow": "0 0 15px -3px rgba(0, 120, 212, 0.15)",
      },
    },
  },
  plugins: [],
};
