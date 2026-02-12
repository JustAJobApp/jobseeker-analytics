"use client";

import { useState, useEffect } from "react";
import NextLink from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import posthog from "posthog-js";

import { siteConfig } from "@/config/site";
import { ThemeSwitch } from "@/components/theme-switch";
import { checkAuth } from "@/utils/auth";

const ExternalLinkIcon = ({ className = "w-3 h-3" }: { className?: string }) => (
	<svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
		<path
			d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
			strokeLinecap="round"
			strokeLinejoin="round"
			strokeWidth={2}
		/>
	</svg>
);

interface NavbarProps {
	defaultCollapsed?: boolean;
	isPremium?: boolean;
	onSettingsClick?: () => void;
}

export const Navbar = ({ defaultCollapsed = false, isPremium = false, onSettingsClick }: NavbarProps) => {
	const [isOpen, setIsOpen] = useState(false);
	const [isCollapsed, setIsCollapsed] = useState(defaultCollapsed);
	const [isAuthenticated, setIsAuthenticated] = useState(false);
	const pathname = usePathname();
	const { theme } = useTheme();
	const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

	useEffect(() => {
		const checkUserStatus = async () => {
			const authenticated = await checkAuth(apiUrl);
			setIsAuthenticated(authenticated);
		};
		checkUserStatus();
	}, [apiUrl]);

	// Handle settings/upgrade click in mobile menu
	const handleMobileSettingsClick = () => {
		posthog.capture(isPremium ? "settings_clicked" : "upgrade_clicked", { source: "navbar_mobile" });
		if (!isAuthenticated) {
			window.location.href = "/login";
			return;
		}
		if (onSettingsClick) {
			onSettingsClick();
		}
	};

	// Determine what the primary CTA button should show
	const getPrimaryCTA = () => {
		if (isAuthenticated && pathname === "/dashboard") {
			return { label: "Logout", href: "/logout" };
		}
		if (isAuthenticated) {
			return { label: "Dashboard", href: "/dashboard" };
		}
		return { label: "Login", href: "/login" };
	};

	const primaryCTA = getPrimaryCTA();

	// Collapsed navbar - just logo and expand button
	if (isCollapsed) {
		return (
			<nav className="sticky top-0 z-50 bg-background dark:bg-content1 shadow-sm">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="flex items-center justify-between h-12">
						<NextLink className="flex items-center gap-2" href="/">
							<img
								alt="JustAJobApp Logo"
								className="h-8 w-8 object-contain"
								src={
									theme === "dark"
										? "/justajobapp-square-dark-monogram-logo-favicon.png"
										: "/justajobapp-circle-monogram-logo-social.png"
								}
							/>
							<span className="text-lg font-semibold text-foreground">{siteConfig.name}</span>
						</NextLink>
						<button
							className="p-1.5 text-default-500 hover:text-foreground rounded-md"
							title="Expand navbar"
							onClick={() => setIsCollapsed(false)}
						>
							<svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path d="M19 9l-7 7-7-7" strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} />
							</svg>
						</button>
					</div>
				</div>
			</nav>
		);
	}

	return (
		<nav className="fixed top-0 left-0 right-0 z-50  bg-background dark:bg-content1 shadow-md border-b border-divider">
			<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
				<div className="flex items-center justify-between h-16">
					{/* Logo and brand - left side */}
					<div className="flex items-center">
						<div className="flex-shrink-0">
							<NextLink className="flex items-center gap-3" href="/">
								<img
									alt="JustAJobApp Logo"
									className="h-10 w-10 object-contain"
									src={
										theme === "dark"
											? "/justajobapp-square-dark-monogram-logo-favicon.png"
											: "/justajobapp-circle-monogram-logo-social.png"
									}
								/>
								<div className="flex flex-col">
									<span className="text-xl font-bold text-foreground">{siteConfig.name}</span>
									<span className="text-xs text-default-500 -mt-1">{siteConfig.description}</span>
								</div>
							</NextLink>
						</div>
					</div>

					{/* Center/Right navigation links and actions */}
					<div className="hidden md:flex items-center space-x-1 lg-nav:space-x-2">
						{/* About dropdown */}
						<div className="relative group">
							<button className="px-2 lg-nav:px-4 py-2 text-sm font-medium text-foreground/80 hover:text-foreground transition-colors flex items-center gap-1">
								About
								<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path
										d="M19 9l-7 7-7-7"
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth={2}
									/>
								</svg>
							</button>
							<div className="absolute left-0 mt-0 w-48 bg-content1 dark:bg-content2 rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 border border-divider">
								<div className="py-1">
									<NextLink
										className="block px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href="/"
									>
										Job Seekers
									</NextLink>
									<NextLink
										className="block px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href="/coaches"
									>
										Career Coaches
									</NextLink>
									<NextLink
										className="block px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href="/pricing"
									>
										Pricing
									</NextLink>
									<NextLink
										className="block px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href="/faq"
									>
										FAQ
									</NextLink>
								</div>
							</div>
						</div>

						{/* Find Jobs - top-level external link */}
						<a
							className="px-2 lg-nav:px-4 py-2 text-sm font-medium text-foreground/80 hover:text-foreground transition-colors flex items-center gap-1"
							href={siteConfig.links.hiringCafe}
							rel="noopener noreferrer"
							target="_blank"
							onClick={() =>
								posthog.capture("resource_link_clicked", { resource: "hiring_cafe", source: "top_nav" })
							}
						>
							Find Real Jobs
							<ExternalLinkIcon />
						</a>

						{/* Resources dropdown */}
						<div className="relative group">
							<button className="px-2 lg-nav:px-4 py-2 text-sm font-medium text-foreground/80 hover:text-foreground transition-colors flex items-center gap-1">
								Resources
								<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path
										d="M19 9l-7 7-7-7"
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth={2}
									/>
								</svg>
							</button>
							<div className="absolute left-0 mt-0 w-56 bg-content1 dark:bg-content2 rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 border border-divider">
								<div className="py-1">
									<a
										className="flex items-center gap-2 px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href={siteConfig.links.hiringCafe}
										rel="noopener noreferrer"
										target="_blank"
										onClick={() =>
											posthog.capture("resource_link_clicked", { resource: "hiring_cafe" })
										}
									>
										Find Real Jobs
										<ExternalLinkIcon />
									</a>
									<a
										className="flex items-center gap-2 px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href={siteConfig.links.neverSearchAlone}
										rel="noopener noreferrer"
										target="_blank"
										onClick={() =>
											posthog.capture("resource_link_clicked", { resource: "never_search_alone" })
										}
									>
										Join a Support Group
										<ExternalLinkIcon />
									</a>
									<a
										className="flex items-center gap-2 px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href={siteConfig.links.samStruanResume}
										rel="noopener noreferrer"
										target="_blank"
										onClick={() =>
											posthog.capture("resource_link_clicked", { resource: "sam_struan_resume" })
										}
									>
										Write a Factual Resume
										<ExternalLinkIcon />
									</a>
								</div>
							</div>
						</div>

						{/* Contribute dropdown */}
						<div className="relative group">
							<button className="px-2 lg-nav:px-4 py-2 text-sm font-medium text-foreground/80 hover:text-foreground transition-colors flex items-center gap-1">
								Contribute
								<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path
										d="M19 9l-7 7-7-7"
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth={2}
									/>
								</svg>
							</button>
							<div className="absolute left-0 mt-0 w-48 bg-content1 dark:bg-content2 rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 border border-divider">
								<div className="py-1">
									<a
										className="flex items-center gap-2 px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href={siteConfig.links.donate}
										rel="noopener noreferrer"
										target="_blank"
									>
										Donate
										<ExternalLinkIcon />
									</a>
									<a
										className="flex items-center gap-2 px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href="/contributors"
									>
										Develop
									</a>
									<a
										className="flex items-center gap-2 px-4 py-2 text-sm text-foreground/80 hover:text-foreground hover:bg-content2 dark:hover:bg-content3"
										href={siteConfig.links.feedback}
										rel="noopener noreferrer"
										target="_blank"
									>
										Give Feedback
										<ExternalLinkIcon />
									</a>
								</div>
							</div>
						</div>

						<ThemeSwitch />

						{/* Back to Dashboard button and Logout icon - shown when authenticated and not on dashboard */}
						{isAuthenticated && pathname !== "/dashboard" && (
							<>
								<NextLink
									className="inline-flex items-center gap-2 px-3 lg-nav:px-4 py-2 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary-600 transition-colors"
									href="/dashboard"
								>
									<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path
											d="M10 19l-7-7m0 0l7-7m-7 7h18"
											strokeLinecap="round"
											strokeLinejoin="round"
											strokeWidth={2}
										/>
									</svg>
									Back to Dashboard
								</NextLink>
								<div className="relative group">
									<NextLink
										className="p-2 text-default-500 hover:text-foreground transition-colors block"
										href="/settings"
									>
										<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path
												d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
											<path
												d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
										</svg>
									</NextLink>
									<div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 dark:bg-gray-700 rounded opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50">
										Settings
									</div>
								</div>
								<div className="relative group">
									<NextLink
										className="p-2 text-default-500 hover:text-foreground transition-colors block"
										href="/logout"
									>
										<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path
												d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
										</svg>
									</NextLink>
									<div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 dark:bg-gray-700 rounded opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50">
										Logout
									</div>
								</div>
							</>
						)}

						{/* Primary CTA button (Dashboard or Login) - only show when not authenticated or on dashboard */}
						{(!isAuthenticated || pathname === "/dashboard") && (
							<NextLink
								className="ml-2 lg-nav:ml-4 inline-flex items-center px-3 lg-nav:px-5 py-2 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary-600 transition-colors"
								href={primaryCTA.href}
							>
								{primaryCTA.label}
							</NextLink>
						)}

						{/* Settings/Upgrade button - shows gear for premium, heart for free */}
						{isAuthenticated && onSettingsClick ? (
							<div className="relative group ml-6">
								<button
									className="p-2.5 border border-divider rounded-md text-default-500 hover:text-foreground hover:border-default-400 transition-colors"
									onClick={() => {
										posthog.capture(isPremium ? "settings_clicked" : "upgrade_clicked", {
											source: "navbar"
										});
										onSettingsClick();
									}}
								>
									{isPremium ? (
										/* Gear icon for premium users */
										<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path
												d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
											<path
												d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
										</svg>
									) : (
										/* Heart icon for free users */
										<svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
											<path
												clipRule="evenodd"
												d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z"
												fillRule="evenodd"
											/>
										</svg>
									)}
								</button>
								<div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 dark:bg-gray-700 rounded opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50">
									{isPremium ? "Settings" : "Upgrade to Premium"}
								</div>
							</div>
						) : !isAuthenticated ? (
							<div className="relative group ml-6">
								<a
									className="p-2.5 border border-divider rounded-md text-default-500 hover:text-foreground hover:border-default-400 transition-colors block"
									href={siteConfig.links.donate}
									rel="noopener noreferrer"
									target="_blank"
								>
									<svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
										<path
											clipRule="evenodd"
											d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z"
											fillRule="evenodd"
										/>
									</svg>
								</a>
								<div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 dark:bg-gray-700 rounded opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50">
									Donate
								</div>
							</div>
						) : null}
					</div>

					{/* Mobile menu button */}
					<div className="-mr-2 flex md:hidden">
						<button
							aria-controls="mobile-menu"
							aria-expanded="false"
							className="bg-content2 inline-flex items-center justify-center p-2 rounded-md text-foreground/80 hover:text-foreground hover:bg-content3 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
							type="button"
							onClick={() => setIsOpen(!isOpen)}
						>
							<span className="sr-only">Open main menu</span>
							{!isOpen ? (
								<svg
									aria-hidden="true"
									className="block h-6 w-6"
									fill="none"
									stroke="currentColor"
									viewBox="0 0 24 24"
									xmlns="http://www.w3.org/2000/svg"
								>
									<path
										d="M4 6h16M4 12h16M4 18h16"
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth="2"
									/>
								</svg>
							) : (
								<svg
									aria-hidden="true"
									className="block h-6 w-6"
									fill="none"
									stroke="currentColor"
									viewBox="0 0 24 24"
									xmlns="http://www.w3.org/2000/svg"
								>
									<path
										d="M6 18L18 6M6 6l12 12"
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth="2"
									/>
								</svg>
							)}
						</button>
					</div>
				</div>
			</div>

			{/* Mobile menu */}
			{isOpen && (
				<div className="md:hidden bg-background dark:bg-content1 border-t border-divider" id="mobile-menu">
					<div className="px-2 pt-2 pb-3 space-y-1">
						{/* About section */}
						<div className="px-3 py-2 text-xs font-semibold text-default-500 uppercase tracking-wider">
							About
						</div>
						<NextLink
							className="block px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href="/"
							onClick={() => setIsOpen(false)}
						>
							Job Seekers
						</NextLink>
						<NextLink
							className="block px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href="/coaches"
							onClick={() => setIsOpen(false)}
						>
							Career Coaches
						</NextLink>
						<NextLink
							className="block px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href="/pricing"
							onClick={() => setIsOpen(false)}
						>
							Pricing
						</NextLink>
						<NextLink
							className="block px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href="/faq"
							onClick={() => setIsOpen(false)}
						>
							FAQ
						</NextLink>

						{/* Resources section */}
						<div className="px-3 py-2 pt-4 text-xs font-semibold text-default-500 uppercase tracking-wider border-t border-divider">
							Resources
						</div>
						<a
							className="flex items-center gap-2 px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href={siteConfig.links.hiringCafe}
							rel="noopener noreferrer"
							target="_blank"
							onClick={() => {
								posthog.capture("resource_link_clicked", {
									resource: "hiring_cafe",
									source: "mobile_menu"
								});
								setIsOpen(false);
							}}
						>
							Real Jobs
							<ExternalLinkIcon />
						</a>
						<a
							className="flex items-center gap-2 px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href={siteConfig.links.neverSearchAlone}
							rel="noopener noreferrer"
							target="_blank"
							onClick={() => {
								posthog.capture("resource_link_clicked", {
									resource: "never_search_alone",
									source: "mobile_menu"
								});
								setIsOpen(false);
							}}
						>
							Job Search Councils (Never Search Alone)
							<ExternalLinkIcon />
						</a>
						<a
							className="flex items-center gap-2 px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href={siteConfig.links.samStruanResume}
							rel="noopener noreferrer"
							target="_blank"
							onClick={() => {
								posthog.capture("resource_link_clicked", {
									resource: "sam_struan_resume",
									source: "mobile_menu"
								});
								setIsOpen(false);
							}}
						>
							Resume Writing (Sam Struan)
							<ExternalLinkIcon />
						</a>
						<a
							className="flex items-center gap-2 px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href={siteConfig.links.githubIssues}
							rel="noopener noreferrer"
							target="_blank"
							onClick={() => setIsOpen(false)}
						>
							Report a Bug / Request Feature
							<ExternalLinkIcon />
						</a>

						{/* Contribute section */}
						<div className="px-3 py-2 pt-4 text-xs font-semibold text-default-500 uppercase tracking-wider border-t border-divider">
							Contribute
						</div>
						{isAuthenticated && onSettingsClick ? (
							<button
								className="block w-full text-left px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
								onClick={() => {
									setIsOpen(false);
									handleMobileSettingsClick();
								}}
							>
								{isPremium ? "Manage Subscription" : "Upgrade to Premium"}
							</button>
						) : (
							<a
								className="flex items-center gap-2 px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
								href={siteConfig.links.donate}
								rel="noopener noreferrer"
								target="_blank"
								onClick={() => setIsOpen(false)}
							>
								Donate
								<ExternalLinkIcon />
							</a>
						)}
						<NextLink
							className="block px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href="/contributors"
							onClick={() => setIsOpen(false)}
						>
							Participate
						</NextLink>
						<a
							className="flex items-center gap-2 px-3 py-2 pl-6 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
							href={siteConfig.links.feedback}
							rel="noopener noreferrer"
							target="_blank"
							onClick={() => setIsOpen(false)}
						>
							Give Feedback
							<ExternalLinkIcon />
						</a>

						{/* Auth section */}
						<div className="pt-4 border-t border-divider">
							{isAuthenticated && (
								<NextLink
									className="block px-3 py-2 rounded-md text-base font-medium text-foreground/80 hover:bg-content2 hover:text-foreground"
									href="/settings"
									onClick={() => setIsOpen(false)}
								>
									Settings
								</NextLink>
							)}
							<NextLink
								className={`block px-3 py-2 rounded-md text-base font-medium transition-colors ${
									pathname === primaryCTA.href
										? "bg-primary text-primary-foreground"
										: "text-foreground/80 hover:bg-content2 hover:text-foreground"
								}`}
								href={primaryCTA.href}
								onClick={() => setIsOpen(false)}
							>
								{primaryCTA.label}
							</NextLink>
							{isAuthenticated && pathname !== "/dashboard" && (
								<NextLink
									className="block px-3 py-2 mt-1 rounded-md text-base font-medium text-foreground/80 hover:text-foreground hover:bg-content2"
									href="/logout"
									onClick={() => setIsOpen(false)}
								>
									Log out
								</NextLink>
							)}
						</div>
					</div>
				</div>
			)}
		</nav>
	);
};
