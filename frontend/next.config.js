/** @type {import('next').NextConfig} */
const nextConfig = {
	output: "standalone",
	// Disable X-Powered-By header to prevent technology fingerprinting
	poweredByHeader: false,
	// Ensure experimental features are removed
	experimental: {
		// Remove any experimental features
	},

	// Security headers to prevent clickjacking and technology disclosure
	async headers() {
		const securityHeaders = [
			{
				key: "X-Frame-Options",
				value: "DENY"
			},
			{
				key: "Content-Security-Policy",
				value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://app.termly.io https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://app.termly.io; frame-src https://www.google.com/recaptcha/; frame-ancestors 'none'"
			},
			{
				key: "X-Content-Type-Options",
				value: "nosniff"
			},
			{
				key: "Referrer-Policy",
				value: "strict-origin-when-cross-origin"
			}
		];

		return [
			{
				// Static assets - allow caching (immutable, hashed filenames)
				source: "/_next/static/:path*",
				headers: [
					...securityHeaders,
					{
						key: "Cache-Control",
						value: "public, max-age=31536000, immutable"
					}
				]
			},
			{
				// Public static files (fonts, images in public/)
				source: "/static/:path*",
				headers: [
					...securityHeaders,
					{
						key: "Cache-Control",
						value: "public, max-age=31536000, immutable"
					}
				]
			},
			{
				// HTML pages and API routes - no caching
				source: "/:path*",
				headers: [
					...securityHeaders,
					{
						key: "Cache-Control",
						value: "private, no-cache, no-store, max-age=0, s-maxage=0, must-revalidate"
					}
				]
			}
		];
	},

	// Add PostHog rewrites
	async rewrites() {
		return [
			{
				source: "/ingest/static/:path*",
				destination: "https://us-assets.i.posthog.com/static/:path*"
			},
			{
				source: "/ingest/:path*",
				destination: "https://us.i.posthog.com/:path*"
			}
		];
	},

	// Required to support PostHog trailing slash API requests
	skipTrailingSlashRedirect: true
};

module.exports = nextConfig;
