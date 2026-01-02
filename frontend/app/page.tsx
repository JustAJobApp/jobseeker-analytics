"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@heroui/react";

import { Navbar } from "@/components/navbar";
import { siteConfig } from "@/config/site";

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
		<div className="flex flex-col min-h-screen overflow-x-hidden">
			<main className="flex-grow bg-gradient-to-b from-background to-background/95">
				<Navbar />
				<div className="w-full bg-gradient-to-b from-amber-50/60 to-transparent dark:from-gray-800/30 border-b border-amber-100/40 dark:border-emerald-900/30">
					<div className="container mx-auto px-4 py-16 sm:py-24 max-w-5xl">
						<div className="text-center">
							<h1 className="text-4xl font-bold tracking-tight sm:text-6xl bg-clip-text text-transparent bg-gradient-to-r pb-4 from-amber-600 to-emerald-600">
								A single lost email cost me $40,000.
							</h1>
							<p className="mt-4 text-lg max-w-3xl mx-auto text-gray-600 dark:text-gray-300">
								After being laid off by email in 2024, I managed 46 interview pipelines from 129
								applications. During a 9-interview week, a manual tracking error led to a missed
								interview for a role paying $40,000 more than the offers I received.
							</p>
							<div className="mt-10 flex justify-center">
								<a
									className="inline-flex items-center justify-center px-8 py-4 border border-transparent text-base font-medium rounded-md text-black bg-yellow-400 hover:bg-yellow-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition-all duration-200 transform hover:scale-105"
									href="https://its.justajobapp.com/?utm_source=homepage&utm_campaign=new_job_seekers_1"
									rel="noopener noreferrer"
									target="_blank"
								>
									Join the waitlist and never miss an opportunity →
								</a>
							</div>
							<div className="mt-8">
								<p className="text-sm text-gray-500">
									Already a beta tester?{" "}
									<a className="font-medium text-emerald-600 hover:text-emerald-500" href="/login">
										Login here
									</a>
									.
								</p>
							</div>
						</div>
					</div>
				</div>

				<section className="bg-white dark:bg-gray-900 py-16 border-b border-amber-100/40 dark:border-emerald-900/40">
					<div className="container mx-auto px-4 max-w-6xl">
						<div className="text-center mb-12">
							<h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
								The Old Way Isn't Working.
							</h2>
							<p className="mt-4 text-lg leading-8 text-gray-600 dark:text-gray-300">
								Spreadsheets and manual tracking are failing you. It's time for an upgrade.
							</p>
						</div>
						<div className="grid gap-8 md:grid-cols-2 max-w-3xl mx-auto">
							<div className="rounded-2xl border border-amber-100 dark:border-amber-900/40 bg-gradient-to-b from-amber-50/70 to-white dark:from-amber-950/20 dark:to-gray-900 p-6 shadow-sm">
								<h3 className="text-xl font-semibold mb-3 text-amber-800 dark:text-amber-200">
									New Job Seekers
								</h3>
								<p className="text-gray-700 dark:text-gray-200 mb-6">
									Want access? Request an invite for the inbox-powered tracker.
								</p>
								<a
									className="inline-flex w-full items-center justify-center px-4 py-2 text-sm font-semibold rounded-md text-black bg-yellow-400 hover:bg-yellow-500 transition-colors"
									href="https://its.justajobapp.com/?utm_source=homepage&utm_campaign=new_job_seekers_2"
									rel="noopener noreferrer"
									target="_blank"
								>
									Join the waitlist
								</a>
							</div>
							<div
								className="rounded-2xl border border-gray-200 dark:border-gray-700 bg-gradient-to-b from-white to-gray-50 dark:from-gray-900 dark:to-gray-800 p-6 shadow-sm"
								id="beta-testers"
							>
								<h3 className="text-xl font-semibold mb-3 text-gray-900 dark:text-white">
									Already a Beta Tester?
								</h3>
								<p className="text-gray-700 dark:text-gray-200 mb-6">Login below.</p>
								<BetaLoginButton fullWidth />
							</div>
						</div>
					</div>
				</section>
			</main>

			{/* Problem/Agitation Section */}
			<div className="bg-gray-50 dark:bg-gray-900/40">
				<div className="mx-auto max-w-4xl px-6 lg:px-8 text-center py-8">
					<h2 className="text-3xl font-bold tracking-tight sm:text-4xl">The Job Search Crisis</h2>
					<ul className="mt-4 list-disc list-inside space-y-2 text-lg leading-8 text-gray-600 dark:text-gray-300">
						<li>
							<strong>12x the Noise:</strong> Unemployed seekers do 12 times more work to find a job than
							people who already have one. This means 12 times more emails and links to track.
						</li>
						<li>
							<strong>3x More Applications:</strong> In 2024, it took 3 times as many applications to get
							a single hire compared to 2021. The sheer volume of "Thank you for applying" emails has
							tripled.
						</li>
						<li>
							<strong>1 Million People Laid Off:</strong> As of October 2025, 1 million U.S. workers are
							exposed to job searches with high email volume.
						</li>
					</ul>
				</div>
				{/* Placeholder for dashboard GIF */}
				<div
					className="bg-gray-200 dark:bg-gray-700 h-96 w-full rounded-lg flex items-center justify-center cursor-pointer hover:opacity-90 transition-opacity"
					onClick={() => {
						setPopupImageSrc("homepage/Problem-Email.png");
						setShowImagePopup(true);
					}}
				>
					<div className="relative">
						<img
							alt="Clean, modern dashboard showing automated application tracking"
							className="max-h-80 max-w-full object-contain"
							src="homepage/Problem-Email.png"
						/>
						<div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-20 opacity-0 hover:opacity-100 transition-opacity">
							<svg
								className="h-12 w-12 text-white"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
								xmlns="http://www.w3.org/2000/svg"
							>
								<path
									d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v6m4-3H6"
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
								/>
							</svg>
						</div>
					</div>
				</div>
				<div className="mx-auto max-w-4xl px-6 lg:px-8 text-center py-24">
					<h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
						Spreadsheets and Notes Aren't Helping
					</h2>
					<ul className="mt-4 list-disc list-inside space-y-2 text-lg leading-8 text-gray-600 dark:text-gray-300">
						<li>
							<strong>The 3-Tool Mess:</strong> 72% (16 of 22) of surveyed job seekers try to fix this by
							using 3 or more different apps at once.
						</li>
						<li>
							<strong>The Result:</strong> Moving data between emails, calendars, and spreadsheets
							manually is where the $40,000 mistakes happen.
						</li>
					</ul>
				</div>
			</div>
			{/* Placeholder for dashboard GIF */}
			<div
				className="bg-gray-200 dark:bg-gray-700 h-96 w-full rounded-lg flex items-center justify-center cursor-pointer hover:opacity-90 transition-opacity"
				onClick={() => {
					setPopupImageSrc("homepage/Solution-Light.png");
					setShowImagePopup(true);
				}}
			>
				<div className="relative">
					<img
						alt="Clean, modern dashboard showing automated application tracking"
						className="max-h-80 max-w-full object-contain"
						src="homepage/Solution-Light.png"
					/>
					<div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-20 opacity-0 hover:opacity-100 transition-opacity">
						<svg
							className="h-12 w-12 text-white"
							fill="none"
							stroke="currentColor"
							viewBox="0 0 24 24"
							xmlns="http://www.w3.org/2000/svg"
						>
							<path
								d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v6m4-3H6"
								strokeLinecap="round"
								strokeLinejoin="round"
								strokeWidth={2}
							/>
						</svg>
					</div>
				</div>
			</div>
			{/* Solution / Value Prop Section */}
			<div className="bg-white dark:bg-gray-900 py-24">
				<div className="mx-auto max-w-7xl px-6 lg:px-8">
					<div className="grid grid-cols-1 md:grid-cols-2 gap-16 items-center">
						<div>
							<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-gray-900 dark:text-white">
								Solution: An Email-Synced Zero-Click Interview Tracker
							</h2>
							<p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
								JustAJobApp.com connects securely to your email inbox to automatically sync interviews
								from recruiter emails into a web dashboard.
							</p>
						</div>
						<div>
							{/* Placeholder for dashboard GIF */}
							<div
								className="bg-gray-200 dark:bg-gray-700 h-96 w-full rounded-lg flex items-center justify-center cursor-pointer hover:opacity-90 transition-opacity"
								onClick={() => {
									setPopupImageSrc("homepage/Solution-Screenshot.png");
									setShowImagePopup(true);
								}}
							>
								<div className="relative">
									<img
										alt="Clean, modern dashboard showing automated application tracking"
										className="max-h-80 max-w-full object-contain"
										src="homepage/Solution-Screenshot.png"
									/>
									<div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-20 opacity-0 hover:opacity-100 transition-opacity">
										<svg
											className="h-12 w-12 text-white"
											fill="none"
											stroke="currentColor"
											viewBox="0 0 24 24"
											xmlns="http://www.w3.org/2000/svg"
										>
											<path
												d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v6m4-3H6"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
										</svg>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* Differentiator Section */}
			<div className="py-24">
				<div className="mx-auto max-w-4xl px-6 lg:px-8 text-center">
					<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-gray-900 dark:text-white">
						Stop Clicking. Start Automating.
					</h2>
					<p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
						Unlike other job trackers that force you to literally click on every job with a browser
						extension, JustAJobApp.com is automated.
					</p>
					<p className="mt-4 text-lg leading-8 text-gray-600 dark:text-gray-300">
						Apply for a job. Get a confirmation email. That's it. Your tracker is now up to date.
					</p>
				</div>
			</div>

			{/* Social Proof / Testimonials Section */}
			<div className="bg-white dark:bg-gray-900 py-24">
				<div className="mx-auto max-w-4xl px-6 lg:px-8">
					<div className="text-center mb-10">
						<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-gray-900 dark:text-white">
							Why 100+ Beta Testers Ditched Their Spreadsheets
						</h2>
					</div>
					<div className="space-y-10">
						<div className="bg-gradient-to-r from-amber-50 to-emerald-50 dark:from-amber-950/30 dark:to-emerald-950/30 rounded-xl p-8 border border-amber-200 dark:border-amber-800/50">
							<div className="flex items-start gap-4">
								<div className="flex-shrink-0">
									<svg className="w-8 h-8 text-amber-600" fill="currentColor" viewBox="0 0 24 24">
										<path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h4v10h-10z" />
									</svg>
								</div>
								<div className="flex-1">
									<blockquote className="text-lg italic text-gray-700 dark:text-gray-300 leading-relaxed">
										"I receive so many emails a day that I mistook one for a rejection. Later, I saw
										a color-coded 'Hiring Freeze' status in JustAJobApp that caught my eye. It
										prompted me to go back and find the email—it wasn't a rejection, but an
										invitation to apply for a reopened position.{" "}
										<strong>
											I would have completely missed this opportunity if it wasn't for
											JustAJobApp.
										</strong>
										"
									</blockquote>
									<div className="mt-4 text-sm font-semibold text-gray-900 dark:text-white">
										Computer Science & Engineering New Grad (May 2025), F1-OPT
									</div>
								</div>
							</div>
						</div>
						<div className="bg-gradient-to-r from-emerald-50 to-amber-50 dark:from-emerald-950/30 dark:to-amber-950/30 rounded-xl p-8 border border-emerald-200 dark:border-emerald-800/50">
							<div className="flex items-start gap-4">
								<div className="flex-shrink-0">
									<svg className="w-8 h-8 text-emerald-600" fill="currentColor" viewBox="0 0 24 24">
										<path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h4v10h-10z" />
									</svg>
								</div>
								<div className="flex-1">
									<blockquote className="text-lg italic text-gray-700 dark:text-gray-300 leading-relaxed">
										"I get to see the entire picture on a single dashboard... and{" "}
										<strong>not have to continually update a spreadsheet.</strong>"
									</blockquote>
									<div className="mt-4 text-sm font-semibold text-gray-900 dark:text-white">
										Donal Murphy, MBA, Global Events Producer
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* Founder's Story / Credibility Section */}
			<div className="py-24">
				<div className="mx-auto max-w-7xl px-6 lg:px-8">
					<div className="grid grid-cols-1 md:grid-cols-4 gap-12 items-center">
						<div className="md:col-span-2">
							{/* Founder Image with click functionality */}
							<div
								className="bg-gray-200 dark:bg-gray-700 rounded-lg overflow-hidden cursor-pointer hover:opacity-90 transition-opacity"
								onClick={() => {
									setPopupImageSrc("homepage/News.png");
									setShowImagePopup(true);
								}}
							>
								<div className="relative">
									<img
										alt="Founder of Just A Job App"
										className="max-h-80 max-w-full object-contain"
										src="homepage/News.png"
									/>
									<div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-20 opacity-0 hover:opacity-100 transition-opacity">
										<svg
											className="h-8 w-8 text-white"
											fill="none"
											stroke="currentColor"
											viewBox="0 0 24 24"
											xmlns="http://www.w3.org/2000/svg"
										>
											<path
												d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v6m4-3H6"
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
											/>
										</svg>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* Future Vision / Coming Soon Section */}
			<div className="bg-gray-50 dark:bg-gray-900/60 py-24">
				<div className="mx-auto max-w-7xl px-6 lg:px-8">
					<div className="mx-auto max-w-2xl lg:text-center">
						<h2 className="text-3xl font-bold tracking-tight sm:text-4xl text-gray-900 dark:text-white">
							Coming Soon: Instant Interview Prep
						</h2>
						<p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
							Tracking your applications is just the beginning. The next feature on our roadmap is{" "}
							<strong>Instant Interview Prep.</strong>
						</p>
						<p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
							Customer discovery with 32 job seekers in 2025 confirmed that 56% could not locate job
							descriptions or notes immediately before an interview.
						</p>
						<p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
							Upon detection of an emailed calendar invite, JustAJobApp will identify interviewers, draft
							company-specific questions, and map key talking points from your resume to the autosaved job
							description requirements.
						</p>
						<p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
							Optionally, JustAJobApp will notify{" "}
							<a className="font-medium text-emerald-600 hover:text-emerald-500" href="/coaches">
								your career coach
							</a>{" "}
							of your upcoming interview to help you prepare.
						</p>
					</div>
				</div>
			</div>

			{/* (Removed FAQ per spec) */}

			{/* Final Call to Action Section */}

			<section className="w-full px-4 py-16" id="waitlist">
				<div className="max-w-4xl mx-auto">
					<div className="bg-gradient-to-r from-amber-50 to-emerald-50 dark:from-amber-950/30 dark:to-emerald-950/30 rounded-xl p-6 sm:p-8 border border-amber-200 dark:border-amber-800/50 text-center transition-all">
						<h2 className="text-2xl sm:text-3xl font-bold mb-6 bg-clip-text text-transparent bg-gradient-to-r from-amber-600 to-emerald-600 dark:from-amber-500 dark:to-emerald-400">
							{siteConfig.description}
						</h2>
						<p className="text-base sm:text-lg text-gray-700 dark:text-gray-300 mb-8 leading-relaxed">
							Win your next interview without the out-of-date spreadsheet.
						</p>

						<div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-8 border border-gray-200 dark:border-gray-700">
							<div className="grid gap-4 md:grid-cols-2 justify-center">
								<div className="rounded-xl border border-amber-100 dark:border-amber-900/50 p-4">
									<h4 className="font-semibold text-amber-800 dark:text-amber-200 mb-2">
										New Job Seekers
									</h4>
									<p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
										Request an invite to get in line for the inbox-powered tracker.
									</p>
									<a
										className="inline-flex w-full items-center justify-center px-4 py-2 text-sm font-semibold rounded-md text-black bg-yellow-400 hover:bg-yellow-500 transition-colors"
										href="https://its.justajobapp.com/?utm_source=homepage&utm_campaign=new_job_seekers_3"
										rel="noopener noreferrer"
										target="_blank"
									>
										Join the waitlist
									</a>
								</div>
								<div className="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
									<h4 className="font-semibold text-gray-900 dark:text-white mb-2">Beta Testers</h4>
									<p className="text-sm text-gray-600 dark:text-gray-300 mb-4">Login below.</p>
									<BetaLoginButton fullWidth />
								</div>
							</div>
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
						<div className="bg-white flex justify-center dark:bg-gray-800 p-6 rounded-lg shadow-2xl overflow-hidden">
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
