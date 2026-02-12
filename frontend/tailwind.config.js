import { heroui } from "@heroui/theme";

/** @type {import('tailwindcss').Config} */
export default {
	content: [
		"./components/**/*.{js,ts,jsx,tsx,mdx}",
		"./app/**/*.{js,ts,jsx,tsx,mdx}",
		"./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}"
	],
	theme: {
		extend: {
			screens: {
				"lg-nav": "926px"
			},
			fontFamily: {
				sans: ["var(--font-sans)"],
				mono: ["var(--font-mono)"]
			}
		}
	},
	darkMode: "class",
	plugins: [
		heroui({
			themes: {
				dark: {
					colors: {
						background: "#0B2918", // Aztec - Main page background
						foreground: "#F3F6F2", // Snow Drift - Main body text
						primary: {
							50: "#FFF8E6",
							100: "#FFEDB3",
							400: "#FFC91A",
							500: "#FFAC00", // Sun - Buttons, Active states, Links
							600: "#CC8A00",
							700: "#996700",
							DEFAULT: "#FFAC00",
							foreground: "#0B2918" // Dark text on primary for contrast
						},
						content1: "#143522", // Elevated Aztec - Cards
						content2: "#1c412c", // Custom - Sidebars / Input fields
						content3: "#245A3D",
						focus: "#FFAC00",
						divider: "#3A8058",
						default: {
							100: "#E8ECE6",
							200: "#D4DCD0",
							500: "#92AB90", // Envy - Secondary text / Metadata
							600: "#748A72",
							DEFAULT: "#92AB90",
							foreground: "#F3F6F2"
						}
					}
				},
				light: {
					colors: {
						background: "#FFFFFF",
						foreground: "#1A1A1A",
						primary: {
							50: "#FFF8E6",
							100: "#FFEDB3",
							400: "#FFC91A",
							500: "#FFAC00", // Sun for light mode contrast
							600: "#A67000",
							700: "#805600",
							DEFAULT: "#FFAC00",
							foreground: "#1A1A1A"
						},
						content1: "#FAFAFA",
						content2: "#F5F5F5",
						content3: "#EEEEEE",
						focus: "#CC8A00",
						default: {
							100: "#E8ECE6",
							200: "#D4DCD0",
							500: "#6B8A60",
							600: "#748A72",
							DEFAULT: "#6B8A60"
						}
					}
				}
			}
		})
	]
};
