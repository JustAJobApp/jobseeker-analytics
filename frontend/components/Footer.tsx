"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import NextLink from "next/link";

import { siteConfig } from "@/config/site";

const ExternalLinkIcon = () => (
	<svg className="inline-block w-3 h-3 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
		<path
			d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
			strokeLinecap="round"
			strokeLinejoin="round"
			strokeWidth={2}
		/>
	</svg>
);

const Footer = () => {
	const [isPremium, setIsPremium] = useState(false);
	const [isLoading, setIsLoading] = useState(false);
	const apiUrl = process.env.NEXT_PUBLIC_API_URL;
	const router = useRouter();

	useEffect(() => {
		const checkPremiumStatus = async () => {
			if (!apiUrl) return;
			try {
				const response = await fetch(`${apiUrl}/settings/premium-status`, {
					credentials: "include"
				});
				if (response.ok) {
					const data = await response.json();
					setIsPremium(data.is_premium);
				}
			} catch {
				// Silently fail - default to non-premium
			}
		};
		checkPremiumStatus();
	}, [apiUrl]);

	const handleUpgrade = async () => {
		if (!apiUrl) {
			router.push("/pricing");
			return;
		}
		setIsLoading(true);
		try {
			const response = await fetch(`${apiUrl}/payment/checkout`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					amount_cents: 500,
					trigger_type: "footer",
					is_recurring: true
				})
			});
			if (response.ok) {
				const data = await response.json();
				if (data.checkout_url) {
					window.location.href = data.checkout_url;
					return;
				}
			}
			// If checkout fails (not logged in, etc.), redirect to pricing page
			router.push("/pricing");
		} catch {
			router.push("/pricing");
		} finally {
			setIsLoading(false);
		}
	};

	return (
		<footer className="w-full border-t border-divider bg-content1 dark:bg-content1">
			{/* CTA Banner */}
			<div className="bg-primary/10 dark:bg-primary/5 py-6">
				<div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
					<div className="flex flex-col sm:flex-row items-center justify-center gap-4 text-center sm:text-left">
						{isPremium ? (
							<>
								<p className="text-sm sm:text-base text-foreground">
									Something not working correctly? We&apos;d love to hear about it!
								</p>
								<a
									className="inline-flex items-center px-4 py-2 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary-600 transition-colors"
									href={siteConfig.links.bugReport}
									rel="noopener noreferrer"
									target="_blank"
								>
									Give Feedback <ExternalLinkIcon />
								</a>
							</>
						) : (
							<>
								<p className="text-sm sm:text-base text-foreground">
									Your job search moves fast. Let your tracker keep up.
								</p>
								<button
									className="inline-flex items-center px-4 py-2 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary-600 transition-colors disabled:opacity-50"
									disabled={isLoading}
									onClick={handleUpgrade}
								>
									{isLoading ? "Loading..." : "Get updates twice a day →"}
								</button>
							</>
						)}
					</div>
				</div>
			</div>

			{/* Main Footer Content */}
			<div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
				<div className="grid grid-cols-2 md:grid-cols-4 gap-8">
					{/* PRODUCT Column */}
					<div>
						<h4 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">Product</h4>
						<ul className="space-y-3">
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href="/"
								>
									For Job Seekers
								</NextLink>
							</li>
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href="/coaches"
								>
									For Career Coaches
								</NextLink>
							</li>
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href="/faq"
								>
									FAQ
								</NextLink>
							</li>
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href="/pricing"
								>
									Pricing
								</NextLink>
							</li>
						</ul>
					</div>

					{/* RESOURCES Column */}
					<div>
						<h4 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
							Resources
						</h4>
						<ul className="space-y-3">
							<li>
								<a
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.hiringCafe}
									rel="noopener noreferrer"
									target="_blank"
								>
									Find Real Jobs <ExternalLinkIcon />
								</a>
							</li>
							<li>
								<a
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.neverSearchAlone}
									rel="noopener noreferrer"
									target="_blank"
								>
									Join a Support Group <ExternalLinkIcon />
								</a>
							</li>
							<li>
								<a
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.samStruanResume}
									rel="noopener noreferrer"
									target="_blank"
								>
									Write a Factual Resume <ExternalLinkIcon />
								</a>
							</li>
						</ul>
					</div>

					{/* ABOUT Column */}
					<div>
						<h4 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">About</h4>
						<ul className="space-y-3">
							<li>
								<a
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.support}
									rel="noopener noreferrer"
									target="_blank"
								>
									Contact Us
								</a>
							</li>
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.privacyPolicy}
								>
									Privacy Policy
								</NextLink>
							</li>
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.termsAndConditions}
								>
									Terms of Service
								</NextLink>
							</li>
						</ul>
					</div>

					{/* CONTRIBUTE Column */}
					<div>
						<h4 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
							Contribute
						</h4>
						<ul className="space-y-3">
							<li>
								<NextLink
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href="/contributors"
								>
									Develop
								</NextLink>
							</li>
							<li>
								<a
									className="text-sm text-default-500 hover:text-foreground transition-colors"
									href={siteConfig.links.feedback}
									rel="noopener noreferrer"
									target="_blank"
								>
									Give Feedback <ExternalLinkIcon />
								</a>
							</li>
						</ul>
					</div>
				</div>
			</div>

			{/* Copyright */}
			<div className="border-t border-divider py-6">
				<div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
					<p className="text-sm text-default-500 text-center">
						© {new Date().getFullYear()} {siteConfig.legalName} · {siteConfig.description}
					</p>
				</div>
			</div>
		</footer>
	);
};

export default Footer;
