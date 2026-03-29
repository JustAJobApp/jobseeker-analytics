import { Navbar } from "@/components/navbar";
import { siteConfig } from "@/config/site";

const CheckIcon = ({ className = "w-3 h-3" }: { className?: string }) => (
	<svg className={className} fill="none" stroke="currentColor" viewBox="0 0 13 13">
		<path d="M2 6.5l3 3 6-6" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" />
	</svg>
);

const XIcon = ({ className = "w-3 h-3" }: { className?: string }) => (
	<svg className={className} fill="none" stroke="currentColor" viewBox="0 0 13 13">
		<path d="M3 3l7 7M10 3l-7 7" strokeLinecap="round" strokeWidth="1.5" />
	</svg>
);

const GitHubIcon = ({ className = "w-4 h-4" }: { className?: string }) => (
	<svg className={className} fill="currentColor" viewBox="0 0 16 16">
		<path d="M8 1C4.134 1 1 4.134 1 8c0 3.09 2.003 5.71 4.781 6.635.35.064.478-.152.478-.337 0-.166-.006-.605-.009-1.188-1.947.423-2.357-.939-2.357-.939-.318-.808-.777-1.023-.777-1.023-.635-.434.048-.425.048-.425.702.049 1.071.72 1.071.72.624 1.069 1.637.76 2.037.581.064-.452.244-.76.444-.935-1.554-.177-3.188-.777-3.188-3.456 0-.763.272-1.387.72-1.876-.072-.177-.312-.888.068-1.851 0 0 .587-.188 1.923.716A6.694 6.694 0 018 4.78a6.7 6.7 0 011.748.235c1.334-.904 1.92-.716 1.92-.716.381.963.141 1.674.069 1.851.449.489.719 1.113.719 1.876 0 2.686-1.636 3.277-3.194 3.45.251.217.475.644.475 1.297 0 .937-.008 1.691-.008 1.921 0 .187.126.406.481.337C12.998 13.707 15 11.088 15 8c0-3.866-3.134-7-7-7z" />
	</svg>
);

const SecurityPage = () => {
	return (
		<div className="flex flex-col min-h-screen">
			<Navbar />
			<main className="flex-grow pt-16">
				<div className="max-w-3xl mx-auto px-8 py-16">
					{/* Hero */}
					<div className="border-b border-divider pb-10 mb-10">
						<p className="text-xs font-medium tracking-widest uppercase text-emerald-600 dark:text-emerald-400 mb-4">
							Security & Privacy
						</p>
						<h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-4 leading-tight">
							Your data is protected.
							<br />
							Here's the proof.
						</h1>
						<p className="text-lg text-gray-600 dark:text-gray-300 max-w-xl">
							We completed an independent security audit to add the Google email integration. Every step
							was tracked publicly on GitHub. And Google contractually prohibits us from misusing your
							data.
						</p>
					</div>

					{/* The Short Answer Callout */}
					<div className="bg-emerald-100 dark:bg-emerald-900/50 border-l-4 border-emerald-500 rounded-r-lg p-6 mb-10">
						<p className="text-xs font-medium tracking-widest uppercase text-emerald-700 dark:text-emerald-300 mb-2">
							The short answer
						</p>
						<p className="text-gray-800 dark:text-gray-100 leading-relaxed">
							We can only <strong>read</strong> your emails — we cannot send, delete, or modify anything.
							We only look at job-related content using a specific filter that is publicly readable code.
							An independent security firm audited us twice and scored us <strong>9.7 out of 10</strong>{" "}
							before Google approved our access.
						</p>
					</div>

					{/* Data Use Section */}
					<section className="mb-10">
						<h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
							How we are and aren't allowed to use your data
						</h2>
						<p className="text-sm text-gray-600 dark:text-gray-300 mb-4 leading-relaxed">
							Google's API policy contractually binds us — and every app with Gmail access — to a strict
							set of rules about what can and can't be done with your data. These aren't our promises,
							they're enforceable conditions of our access.
						</p>
						<div className="grid md:grid-cols-2 gap-3 mb-4">
							<div className="bg-gray-100 dark:bg-gray-800 rounded-xl p-6">
								<p className="text-xs font-medium tracking-widest uppercase text-emerald-600 dark:text-emerald-400 mb-3 flex items-center gap-2">
									<CheckIcon />
									Allowed
								</p>
								<ul className="space-y-2">
									{[
										"Use data to provide features visible in the app",
										"Share data with your career coach — only with your explicit consent",
										"Use data to investigate security issues",
										"Comply with applicable laws"
									].map((item, i) => (
										<li
											key={i}
											className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2"
										>
											<span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-2 flex-shrink-0" />
											{item}
										</li>
									))}
								</ul>
							</div>
							<div className="bg-gray-100 dark:bg-gray-800 rounded-xl p-6">
								<p className="text-xs font-medium tracking-widest uppercase text-red-600 dark:text-red-400 mb-3 flex items-center gap-2">
									<XIcon />
									Prohibited by Google
								</p>
								<ul className="space-y-2">
									{[
										"Sell data to third parties or data brokers",
										"Use data for advertising or retargeting",
										"Transfer data to anyone without your consent",
										"Use data to assess credit or lending",
										"Let humans read your data without your agreement"
									].map((item, i) => (
										<li
											key={i}
											className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2"
										>
											<span className="w-1.5 h-1.5 rounded-full bg-red-500 mt-2 flex-shrink-0" />
											{item}
										</li>
									))}
								</ul>
							</div>
						</div>
						<div className="bg-gray-100 dark:bg-gray-800 border-l-4 border-gray-400 dark:border-gray-600 rounded-r-lg p-5 text-sm text-gray-700 dark:text-gray-300">
							These requirements come from Google's API Services User Data Policy, which applies to every
							app with access to Gmail data — including ours. Violations result in revocation of API
							access.
							<a
								className="block mt-2 text-xs text-gray-500 dark:text-gray-400 hover:text-primary"
								href={siteConfig.links.googleApiPolicy}
								rel="noopener noreferrer"
								target="_blank"
							>
								Read Google's full policy →
							</a>
						</div>

						{/* Coach Feature Box */}
						<div className="bg-blue-100 dark:bg-blue-900/50 rounded-xl p-6 mt-4">
							<p className="text-xs font-medium tracking-widest uppercase text-blue-700 dark:text-blue-300 mb-2">
								About the career coach feature
							</p>
							<p className="text-sm text-gray-800 dark:text-gray-100 leading-relaxed">
								JustAJobApp has an optional feature where you can share your job search data with a
								career coach. This is the only way your data ever reaches another person — and it
								requires your explicit consent at every step. This is fully compliant with Google's
								policy, which permits transfers "only with the user's consent."
							</p>
							<div className="flex flex-wrap gap-2 mt-4">
								{[
									"You choose to connect with a coach",
									"You explicitly grant them access",
									"You can revoke it at any time"
								].map((step, i) => (
									<div
										key={i}
										className="bg-white dark:bg-gray-800 rounded-lg px-3 py-2 text-xs text-gray-700 dark:text-gray-300 flex items-center gap-2"
									>
										<span className="w-5 h-5 rounded-full bg-blue-200 dark:bg-blue-800 text-blue-700 dark:text-blue-300 text-xs font-medium flex items-center justify-center flex-shrink-0">
											{i + 1}
										</span>
										{step}
									</div>
								))}
							</div>
						</div>
					</section>

					{/* Email Filter Section */}
					<section className="mb-10">
						<h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
							Exactly what we read — and what we skip
						</h2>
						<p className="text-sm text-gray-600 dark:text-gray-300 mb-4 leading-relaxed">
							Our privacy policy commits us to data minimization — we don't request anything beyond what's
							needed for core functionality. In practice, that means a narrow email filter. Here's
							precisely what it matches.
						</p>
						<div className="bg-gray-100 dark:bg-gray-800 rounded-xl p-6">
							<div className="flex items-center justify-between mb-4 flex-wrap gap-2">
								<p className="text-sm font-medium text-gray-900 dark:text-gray-100">
									Email filter — applied before we read anything
								</p>
								<a
									className="text-xs text-primary hover:underline flex items-center gap-1"
									href={siteConfig.links.emailFilterYaml}
									rel="noopener noreferrer"
									target="_blank"
								>
									<GitHubIcon className="w-3 h-3" />
									View full filter on GitHub
								</a>
							</div>
							<div className="grid md:grid-cols-2 gap-6">
								<div>
									<p className="text-xs font-medium tracking-widest uppercase text-emerald-600 dark:text-emerald-400 mb-2">
										Subjects we look for
									</p>
									<div className="flex flex-wrap gap-1.5 mb-2">
										{[
											"thank you for applying",
											"application received",
											"application submitted",
											"interview",
											"next steps",
											"assessment",
											"recruiting screen",
											"your application to",
											"been referred"
										].map((tag) => (
											<span
												key={tag}
												className="text-xs px-2 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300"
											>
												{tag}
											</span>
										))}
									</div>
									<p className="text-xs text-gray-500 dark:text-gray-400">
										+ 25 more job-specific subject patterns
									</p>

									<p className="text-xs font-medium tracking-widest uppercase text-emerald-600 dark:text-emerald-400 mb-2 mt-4">
										Senders we look for
									</p>
									<div className="flex flex-wrap gap-1.5">
										{[
											"careers@",
											"greenhouse.io",
											"ashbyhq.com",
											"smartrecruiters.com",
											"myworkday.com",
											"hire.lever.co",
											"linkedin.com"
										].map((tag) => (
											<span
												key={tag}
												className="text-xs px-2 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300"
											>
												{tag}
											</span>
										))}
									</div>
								</div>
								<div>
									<p className="text-xs font-medium tracking-widest uppercase text-red-600 dark:text-red-400 mb-2">
										Subjects we explicitly skip
									</p>
									<div className="flex flex-wrap gap-1.5 mb-2">
										{[
											"newsletter",
											"blog",
											"% off",
											"farewell",
											"mock interview",
											"welcome to the",
											"sign in link"
										].map((tag) => (
											<span
												key={tag}
												className="text-xs px-2 py-1 rounded-full bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300"
											>
												{tag}
											</span>
										))}
									</div>
									<p className="text-xs text-gray-500 dark:text-gray-400">+ more exclusions</p>

									<p className="text-xs font-medium tracking-widest uppercase text-red-600 dark:text-red-400 mb-2 mt-4">
										Senders we explicitly skip
									</p>
									<div className="flex flex-wrap gap-1.5 mb-2">
										{[
											"newsletter@",
											"github notifications",
											"linkedin digest",
											"substack",
											"info@",
											"support@",
											"hello@"
										].map((tag) => (
											<span
												key={tag}
												className="text-xs px-2 py-1 rounded-full bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300"
											>
												{tag}
											</span>
										))}
									</div>
									<p className="text-xs text-gray-500 dark:text-gray-400">
										+ 15 more excluded senders
									</p>
								</div>
							</div>
						</div>
					</section>

					{/* Audit Section */}
					<section className="mb-10">
						<h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
							The audit: before and after
						</h2>
						<div className="grid md:grid-cols-2 gap-3 mb-4">
							<div className="bg-gray-100 dark:bg-gray-800 rounded-xl p-6">
								<p className="text-xs font-medium tracking-widest uppercase text-gray-500 dark:text-gray-400 mb-2">
									Initial scan — Feb 13, 2026
								</p>
								<p className="text-4xl font-bold text-gray-900 dark:text-gray-100">
									9.4<span className="text-xl text-gray-400 dark:text-gray-500">/10</span>
								</p>
								<p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
									7 findings identified
									<br />
									All marked open — remediation begins
								</p>
							</div>
							<div className="bg-emerald-100 dark:bg-emerald-900/50 rounded-xl p-6">
								<p className="text-xs font-medium tracking-widest uppercase text-emerald-700 dark:text-emerald-300 mb-2">
									After remediation — Feb 16, 2026
								</p>
								<p className="text-4xl font-bold text-emerald-700 dark:text-emerald-300">
									9.7<span className="text-xl text-emerald-500 dark:text-emerald-500">/10</span>
								</p>
								<p className="text-sm text-emerald-800 dark:text-emerald-200 mt-2">
									9 findings total — all patched
									<br />
									Letter of Validation submitted
								</p>
							</div>
						</div>
						<p className="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed">
							The remediation scan uncovered 2 additional issues during deeper testing — both were fixed.
							The score improved from 9.4 to 9.7. No Critical, High, or Medium severity issues were found
							at any point.
						</p>

						{/* Findings Table */}
						<div className="overflow-x-auto mb-6">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b border-divider">
										<th className="text-left text-xs font-medium tracking-widest uppercase text-gray-500 dark:text-gray-400 pb-3 pr-4">
											Finding
										</th>
										<th className="text-left text-xs font-medium tracking-widest uppercase text-gray-500 dark:text-gray-400 pb-3 pr-4">
											Severity
										</th>
										<th className="text-left text-xs font-medium tracking-widest uppercase text-gray-500 dark:text-gray-400 pb-3">
											Status
										</th>
									</tr>
								</thead>
								<tbody>
									{[
										{ finding: "Proxy disclosure", severity: "Low", isNew: false },
										{
											finding: "Subresource integrity attribute missing",
											severity: "Low",
											isNew: false
										},
										{
											finding: "Insufficient site isolation against Spectre",
											severity: "Info",
											isNew: true
										},
										{
											finding: "Strict-transport-security header not set",
											severity: "Info",
											isNew: false
										},
										{
											finding: "Information disclosure via suspicious comments",
											severity: "Info",
											isNew: false
										},
										{
											finding: "Storable but non-cacheable content",
											severity: "Info",
											isNew: true
										},
										{
											finding: "User-controllable HTML element attribute (potential XSS)",
											severity: "Info",
											isNew: false
										},
										{ finding: "Cache-control directives review", severity: "Info", isNew: false },
										{ finding: "User agent fuzzer", severity: "Info", isNew: false }
									].map((row, i) => (
										<tr key={i} className="border-b border-divider last:border-0">
											<td className="py-3 pr-4 text-gray-800 dark:text-gray-200">
												{row.finding}
												{row.isNew && (
													<span className="ml-2 text-xs px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-300">
														new in rescan
													</span>
												)}
											</td>
											<td className="py-3 pr-4">
												<span
													className={`text-xs px-2 py-1 rounded-full ${
														row.severity === "Low"
															? "bg-amber-100 dark:bg-amber-900/50 text-amber-700 dark:text-amber-300"
															: "bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300"
													}`}
												>
													{row.severity}
												</span>
											</td>
											<td className="py-3">
												<span className="text-xs px-2 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">
													Patched
												</span>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>

						{/* GitHub Trail */}
						<div className="bg-gray-100 dark:bg-gray-800 rounded-xl p-6 flex items-center justify-between gap-4 flex-wrap">
							<div>
								<p className="text-sm font-medium text-gray-900 dark:text-gray-100 flex items-center gap-2 flex-wrap">
									Full public audit trail
									<span className="text-xs px-2 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-300 flex items-center gap-1">
										<CheckIcon className="w-3 h-3" />
										68/68 tasks closed
									</span>
								</p>
								<p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
									Every security requirement and finding tracked as a public GitHub issue. All 68
									completed and closed.
								</p>
							</div>
							<a
								className="inline-flex items-center gap-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-full px-4 py-2 text-sm font-medium text-gray-900 dark:text-gray-100 hover:border-gray-400 dark:hover:border-gray-500 transition-colors flex-shrink-0"
								href="https://github.com/JustAJobApp/jobseeker-analytics/issues/101"
								rel="noopener noreferrer"
								target="_blank"
							>
								<GitHubIcon />
								View audit trail on GitHub
							</a>
						</div>
					</section>

					{/* Timeline Section */}
					<section className="mb-10">
						<h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-6">
							How we earned Google's approval
						</h2>
						<div className="relative pl-10">
							<div className="absolute left-[11px] top-2 bottom-2 w-px bg-gray-300 dark:bg-gray-600" />
							{[
								{
									date: "Feb 5, 2025",
									title: "Google notified us a security assessment was required",
									desc: "Any app requesting access to restricted Gmail scopes must pass a mandatory security assessment. We started tracking all 68 requirements publicly on GitHub."
								},
								{
									date: "Feb 13, 2026",
									title: "Initial scan by TAC Security — score 9.4/10",
									desc: "TAC Security, an App Defense Alliance authorized lab, ran the first DAST assessment of the live production app. 7 findings identified; remediation begins immediately."
								},
								{
									date: "Feb 13–16, 2026",
									title: "Remediation scan — score improves to 9.7/10",
									desc: "A deeper follow-up scan found 2 additional informational issues. All 9 total findings patched and verified. No Critical, High, or Medium issues at any stage."
								},
								{
									date: "Mar 5, 2026",
									title: "Letter of Validation submitted to Google",
									desc: "TAC Security submitted our Letter of Validation to Google's Third Party Data Safety Team — confirming all findings resolved and all OWASP ASVS requirements met."
								},
								{
									date: "Mar 6, 2026",
									title: "Google approves our OAuth verification",
									desc: "Google's Third Party Data Safety Team formally approved our app. Both branding and data access verified in Google Cloud Console. We recertify every year."
								}
							].map((item, i) => (
								<div key={i} className="relative mb-6 last:mb-0">
									<div className="absolute -left-10 top-0 w-5 h-5 rounded-full bg-emerald-100 dark:bg-emerald-900/50 border-2 border-emerald-500 flex items-center justify-center">
										<div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
									</div>
									<p className="text-xs font-medium tracking-widest uppercase text-gray-500 dark:text-gray-400 mb-1">
										{item.date}
									</p>
									<p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-0.5">
										{item.title}
									</p>
									<p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">
										{item.desc}
									</p>
								</div>
							))}
						</div>
					</section>

					{/* FAQ Section */}
					<section className="mb-10">
						<h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
							Common questions
						</h2>
						<div className="divide-y divide-divider">
							{[
								{
									q: "Will you read all of my emails?",
									a: (
										<>
											No — and you don't have to take our word for it. Our email filter is public
											code. We only match emails with subjects like "thank you for applying" or
											"interview" from senders like greenhouse.io or careers@ addresses. We
											explicitly skip newsletters, GitHub notifications, LinkedIn digests, and
											anything from info@, support@, or hello@ addresses.{" "}
											<a
												className="text-primary hover:underline"
												href={siteConfig.links.emailFilterYaml}
												rel="noopener noreferrer"
												target="_blank"
											>
												Read the exact filter on GitHub →
											</a>
										</>
									)
								},
								{
									q: "Will you share my data with anyone?",
									a: "The only way your data ever reaches another person is through the optional career coach feature — and only if you explicitly choose to connect with a coach and grant them access. Google's API policy prohibits any other transfers without your consent, and violations result in revocation of our access."
								},
								{
									q: "Can I revoke access?",
									a: "Yes, at any time. Go to myaccount.google.com → Security → Third-party apps with account access, and remove JustAJobApp. Access is instantly revoked."
								},
								{
									q: "Why did this audit happen — did you choose to do it?",
									a: (
										<>
											Google requires it. Any app that accesses restricted Gmail scopes must pass
											a security assessment run by an App Defense Alliance authorized lab before
											Google will approve it. We didn't have a choice — and we think that's a good
											thing. Google also requires us to repeat this every year.
											<div className="bg-gray-100 dark:bg-gray-800 border-l-4 border-gray-400 dark:border-gray-600 rounded-r-lg p-3 mt-3 text-sm text-gray-600 dark:text-gray-400">
												Apps that request access to restricted scopes need to undergo an annual
												security assessment. This assessment verifies that the app can securely
												handle data and delete user data upon request.
												<a
													className="block mt-2 text-xs text-gray-500 dark:text-gray-400 hover:text-primary"
													href="https://support.google.com/cloud/answer/13465431"
													rel="noopener noreferrer"
													target="_blank"
												>
													— Google Cloud documentation →
												</a>
											</div>
										</>
									)
								},
								{
									q: "Do you sell my data?",
									a: "Never — and we can't even if we wanted to. Google's API policy explicitly prohibits transferring or selling user data to third parties, data brokers, or advertising platforms. Our own privacy policy commits us to data minimization: we don't collect anything beyond what's needed to help you track your job search."
								},
								{
									q: "I want to verify everything myself.",
									a: "Go for it. JustAJobApp is fully open source, the audit was conducted against the live production app, all 68 security tasks are documented publicly on GitHub, and the exact email filter we use is readable code."
								}
							].map((item, i) => (
								<div key={i} className="py-4">
									<p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
										{item.q}
									</p>
									<p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{item.a}</p>
								</div>
							))}
						</div>
					</section>

					{/* Contact Strip */}
					<div className="border-t border-divider pt-8 flex items-center justify-between flex-wrap gap-4">
						<p className="text-sm text-gray-600 dark:text-gray-400">
							Still have questions about how we handle your data?
						</p>
						<a
							className="text-sm font-medium text-primary hover:underline"
							href="mailto:lianna@justajobapp.com"
						>
							Contact us →
						</a>
					</div>
				</div>
			</main>
		</div>
	);
};

export default SecurityPage;
