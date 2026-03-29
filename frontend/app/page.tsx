"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@heroui/react";

import { Navbar } from "@/components/navbar";
import { PrivacyFirst } from "@/components/PrivacyFirst";

const Index = () => {
	const [showImagePopup, setShowImagePopup] = useState(false);
	const [popupImageSrc, setPopupImageSrc] = useState("");
	const router = useRouter();

	const handleLogin = () => {
		router.push(`/login`);
	};

	const BetaLoginButton = ({ label = "Login", fullWidth = false }: { label?: string; fullWidth?: boolean }) => (
		<Button
			className={`${fullWidth ? "w-full " : ""}bg-white border-gray-300 text-gray-700 hover:bg-gray-50`}
			variant="bordered"
			onPress={handleLogin}
		>
			{label}
		</Button>
	);

	return (
		<div className="flex flex-col min-h-screen">
			<Navbar />
			<main className="flex-grow">
				<div className="w-full">
					<div className="container mx-auto px-4 py-16 sm:py-24 max-w-5xl">
						<div className="text-center">
							<h1 className="text-4xl font-bold tracking-tight sm:text-6xl text-foreground pb-4">
								A single lost email cost me $40,000.
							</h1>
							<p className="mt-4 text-lg max-w-3xl mx-auto text-foreground/90">
								After being laid off by email in 2024, I managed 46 interview pipelines from 129
								applications. During a 9-interview week, a manual tracking error led to a missed
								interview—for a role paying $40,000 more than the offers I received.
							</p>
							<p className="mt-4 text-xl font-medium max-w-3xl mx-auto text-foreground">
								I built JustAJobApp for other overwhelmed jobseekers.
							</p>
							<div className="mt-10 flex justify-center">
								<a
									className="inline-flex items-center justify-center px-8 py-4 border border-transparent text-base font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary transition-all duration-200 transform hover:scale-105"
									href="/login?signup=true"
								>
									Get Started Free →
								</a>
							</div>
							<div className="mt-8">
								<p className="text-sm text-default-500">
									Already a user?{" "}
									<a
										className="font-medium text-primary hover:text-primary-600 underline"
										href="/login"
									>
										Login here
									</a>
								</p>
							</div>
						</div>
					</div>
				</div>

				{/* How It Works Section */}
				<section className="bg-background dark:bg-content2 py-16 border-b border-divider">
					<div className="container mx-auto px-4 max-w-4xl">
						<div className="text-center mb-12">
							<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-foreground">
								How It Works
							</h2>
						</div>
						<div className="grid gap-8 md:grid-cols-3 max-w-4xl mx-auto">
							<div className="text-center">
								<div className="text-4xl font-bold text-primary mb-4">1</div>
								<h3 className="text-xl font-semibold mb-2 text-foreground">Connect your Gmail</h3>
								<p className="text-foreground/80">Secure sign-in, takes 30 seconds</p>
							</div>
							<div className="text-center">
								<div className="text-4xl font-bold text-primary mb-4">2</div>
								<h3 className="text-xl font-semibold mb-2 text-foreground">
									Apply for jobs like normal
								</h3>
								<p className="text-foreground/80">No browser extensions, no copy pasting</p>
							</div>
							<div className="text-center">
								<div className="text-4xl font-bold text-primary mb-4">3</div>
								<h3 className="text-xl font-semibold mb-2 text-foreground">
									Your dashboard updates automatically
								</h3>
								<p className="text-foreground/80">Confirmation emails become tracked applications</p>
							</div>
						</div>
						<div className="text-center mt-12">
							<p className="text-lg text-foreground/90">
								Unlike other job trackers that force you to manually "clip" every job with a browser
								extension, JustAJobApp is fully automated.
							</p>
						</div>
					</div>
				</section>
			</main>
			<PrivacyFirst />

			{/* Problem/Agitation Section */}
			<div className="bg-gray-50 dark:bg-gray-900/40">
				<div className="mx-auto max-w-4xl px-6 lg:px-8 text-center py-16">
					<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-foreground">
						The Job Search Crisis
					</h2>
					<div className="mt-8 grid gap-6 md:grid-cols-3 text-left">
						<div className="bg-white dark:bg-content2 p-6 rounded-lg shadow">
							<h3 className="text-xl font-bold text-foreground mb-2">2–3× More Applications</h3>
							<p className="text-foreground/80">
								Pre-pandemic research found job seekers sent ~12 applications per month. JustAJobApp
								users send 7–12 per <em>week</em>—over 2× the historical volume.
							</p>
						</div>
						<div className="bg-white dark:bg-content2 p-6 rounded-lg shadow">
							<h3 className="text-xl font-bold text-foreground mb-2">7,800+ Applications Tracked</h3>
							<p className="text-foreground/80">
								That's 7,800+ confirmation emails, status updates, and interview requests our users no
								longer manage manually.
							</p>
						</div>
						<div className="bg-white dark:bg-content2 p-6 rounded-lg shadow">
							<h3 className="text-xl font-bold text-foreground mb-2">Spreadsheets Aren't Helping</h3>
							<p className="text-foreground/80">
								72% of surveyed job seekers use 3+ different apps to track their search. Moving data
								between emails, calendars, and spreadsheets manually is where the $40,000 mistakes
								happen.
							</p>
						</div>
					</div>
				</div>
			</div>

			{/* Social Proof / Testimonials Section */}
			<div className="bg-background dark:bg-content1 py-24">
				<div className="mx-auto max-w-4xl px-6 lg:px-8">
					<div className="text-center mb-10">
						<h2 className="text-sm font-semibold tracking-[0.2em] uppercase text-foreground/50">
							What Job Seekers Are Saying
						</h2>
					</div>
					<div className="space-y-6">
						{/* Top row: two short quotes side by side */}
						<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
							{/* Short quote 1 */}
							<div className="bg-content2 dark:bg-content2 rounded-xl p-8 border border-content3 dark:border-content3 shadow-lg">
								<svg className="w-7 h-7 text-foreground/30 mb-4" fill="currentColor" viewBox="0 0 24 24">
									<path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h4v10h-10z" />
								</svg>
								<blockquote className="text-lg italic text-foreground/85 leading-relaxed mb-6">
									"Job-seeking friends, this app has been a life saver for me!"
								</blockquote>
								<div className="flex items-center gap-3">
									<div className="w-10 h-10 rounded-full bg-slate-500 flex items-center justify-center text-white text-sm font-semibold flex-shrink-0">
										SS
									</div>
									<div>
										<div className="text-sm font-semibold text-foreground">Senior Software Engineer</div>
										<div className="text-xs text-foreground/60">Job seeker</div>
									</div>
								</div>
							</div>
							{/* Short quote 2 */}
							<div className="bg-content2 dark:bg-content2 rounded-xl p-8 border border-content3 dark:border-content3 shadow-lg">
								<svg className="w-7 h-7 text-foreground/30 mb-4" fill="currentColor" viewBox="0 0 24 24">
									<path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h4v10h-10z" />
								</svg>
								<blockquote className="text-lg italic text-foreground/85 leading-relaxed mb-6">
									"I get to see the entire picture on a single dashboard... and not have to continually
									update a spreadsheet."
								</blockquote>
								<div className="flex items-center gap-3">
									<div className="w-10 h-10 rounded-full bg-yellow-700 flex items-center justify-center text-white text-sm font-semibold flex-shrink-0">
										DM
									</div>
									<div>
										<div className="text-sm font-semibold text-foreground">Donal Murphy, MBA</div>
										<div className="text-xs text-foreground/60">Global Events Producer</div>
									</div>
								</div>
							</div>
						</div>
						{/* Bottom: full-width story quote */}
						<div className="bg-content2 dark:bg-content2 rounded-xl p-8 border border-content3 dark:border-content3 shadow-lg">
							<div className="mb-4">
								<span className="inline-block text-xs font-semibold px-3 py-1 rounded-full bg-blue-500/20 text-blue-400 dark:text-blue-300">
									F1-OPT · CS &amp; Engineering
								</span>
							</div>
							<svg className="w-7 h-7 text-foreground/30 mb-4" fill="currentColor" viewBox="0 0 24 24">
								<path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h4v10h-10z" />
							</svg>
							<blockquote className="text-lg italic text-foreground/85 leading-relaxed mb-4">
								"I receive so many emails a day that I mistook one for a rejection. Later, I saw a
								color-coded 'Hiring Freeze' status in JustAJobApp that caught my eye. It prompted me to
								go back and find the email —
							</blockquote>
							<p className="text-base italic px-3 py-2 rounded bg-yellow-700/30 text-yellow-300 dark:text-yellow-200 mb-4">
								it wasn't a rejection, but an invitation to apply for a reopened position.
							</p>
							<blockquote className="text-lg italic text-foreground/85 leading-relaxed mb-6">
								I would have completely missed this opportunity."
							</blockquote>
							<div className="flex items-center gap-3">
								<div className="w-10 h-10 rounded-full bg-green-700 flex items-center justify-center text-white text-sm font-semibold flex-shrink-0">
									CS
								</div>
								<div>
									<div className="text-sm font-semibold text-foreground">CS &amp; Engineering New Grad</div>
									<div className="text-xs text-foreground/60">F1-OPT visa holder</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* As Seen On Section */}
			<div className="py-16 mx-auto">
				<div className="mx-auto max-w-3xl px-6 lg:px-8 text-center">
					<h2 className="text-2xl font-bold tracking-tight sm:text-3xl text-foreground mb-4">
						GitHub's Favorite Open Source Projects of 2025
					</h2>
					<p className="text-lg text-foreground/80 mb-8">
						Featured on GitHub's official YouTube channel (586K subscribers)
					</p>
					<div className="aspect-video">
						<iframe
							allowFullScreen
							allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
							className="rounded-lg"
							frameBorder="0"
							height="100%"
							src="https://www.youtube.com/embed/1ckVnvo-qcw"
							title="GitHub's Favorite Open Source Projects of 2025"
							width="100%"
						/>
					</div>
					<p className="mt-6 text-sm text-foreground/60">
						Also featured on{" "}
						<a
							className="text-primary hover:text-primary-600 underline"
							href="https://youtu.be/sbzKMVaYHZw?t=751"
							rel="noopener noreferrer"
							target="_blank"
						>
							Open Source Friday (July 2025)
						</a>
					</p>
				</div>
			</div>

			{/* Future Vision / Coming Soon Section */}
			<div className="bg-content2 dark:bg-content2 py-24">
				<div className="mx-auto max-w-7xl px-6 lg:px-8">
					<div className="mx-auto max-w-2xl lg:text-center">
						<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-foreground">
							Coming Soon: Paid Plans with Interview Prep
						</h2>
						<p className="mt-6 text-lg leading-8 text-foreground/75">
							The core tracker is <strong>free for jobseekers</strong> as long as we can cover operating
							costs. Paid plans will unlock advanced features like Instant Interview Prep.
						</p>
						<p className="mt-6 text-lg leading-8 text-foreground/75">
							Customer discovery with 32 job seekers confirmed that{" "}
							<strong>
								56% could not locate job descriptions or notes immediately before an interview.
							</strong>
						</p>
						<p className="mt-6 text-lg leading-8 text-foreground/75">
							When JustAJobApp detects an interview on your calendar, it will identify interviewers, draft
							company-specific questions, and map key talking points from your resume to the job
							description.
						</p>
						<div className="mt-10">
							<a
								className="inline-flex items-center justify-center px-6 py-3 border border-transparent text-base font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary-600 transition-colors"
								href="https://its.justajobapp.com/"
								rel="noopener noreferrer"
								target="_blank"
							>
								Join the Waitlist →
							</a>
						</div>
					</div>
				</div>
			</div>

			{/* Final Call to Action Section */}
			<section className="w-full px-4 py-16" id="waitlist">
				<div className="max-w-4xl mx-auto">
					<div className="bg-background/80 dark:bg-content1/80 backdrop-blur-sm rounded-xl p-6 sm:p-8 border-2 border-primary/30 dark:border-primary/20 text-center transition-all shadow-xl">
						<h2 className="text-2xl sm:text-3xl font-bold mb-4 text-foreground">Stop Giving a Click.</h2>
						<p className="text-base sm:text-lg text-foreground/80 mb-8 leading-relaxed">
							Apply for a job. Get a confirmation email. That's it. Your tracker is now up to date.
						</p>

						<div className="flex flex-col sm:flex-row gap-4 justify-center">
							<a
								className="inline-flex items-center justify-center px-8 py-3 text-base font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary-600 transition-colors"
								href="/login?signup=true"
							>
								Get Started Free
							</a>
							<a
								className="inline-flex items-center justify-center px-8 py-3 text-base font-semibold rounded-md border-2 border-gray-300 text-foreground hover:bg-gray-50 dark:hover:bg-content2 transition-colors"
								href="/login"
							>
								Login
							</a>
						</div>
					</div>
				</div>
			</section>

			{/* Image Popup Overlay */}
			{showImagePopup && (
				<div
					className="fixed inset-0 bg-black bg-opacity-80 z-50 flex items-center justify-center p-4"
					onClick={() => setShowImagePopup(false)}
				>
					<div className="relative w-full max-w-6xl">
						<button
							className="absolute -top-12 right-0 text-white hover:text-amber-500 focus:outline-none"
							onClick={(e) => {
								e.stopPropagation();
								setShowImagePopup(false);
							}}
						>
							<svg
								className="h-8 w-8"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
								xmlns="http://www.w3.org/2000/svg"
							>
								<path
									d="M6 18L18 6M6 6l12 12"
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
								/>
							</svg>
						</button>
						<div className="bg-white flex justify-center dark:bg-gray-800 p-6 rounded-lg shadow-2xl">
							<img
								alt="Enlarged image"
								className="h-auto"
								src={popupImageSrc}
								style={{ maxHeight: "90vh" }}
								onClick={(e) => e.stopPropagation()}
							/>
						</div>
					</div>
				</div>
			)}
		</div>
	);
};

export default Index;
