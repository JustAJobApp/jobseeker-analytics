"use client";

import { useEffect, useState, useCallback, useRef, Suspense } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@heroui/react";
import posthog from "posthog-js";

import { GoogleIcon } from "@/components/icons";
import { Navbar } from "@/components/navbar";
import Spinner from "@/components/spinner";
import { checkAuth } from "@/utils/auth";

// ─── Types ────────────────────────────────────────────────────────────────────

type Role = "jobseeker" | "coach";
type Screen =
	| "loading"
	| "step1"
	| "step2"
	| "step3"
	| "step3.5"
	| "step4-scanning"
	| "step4a-i"
	| "step4a-ii"
	| "step4b-i"
	| "step4b-ii"
	| "empty-state";

interface PreviewEmail {
	sender: string;
	sender_domain: string;
	subject: string;
	date: string;
}

const PRESETS = [
	{ value: "1_week", label: "Last week", days: 7 },
	{ value: "1_month", label: "Last month", days: 30 },
	{ value: "3_months", label: "3 months ago", days: 90 },
	{ value: "6_months", label: "6 months ago", days: 180 },
	{ value: "1_year", label: "1 year ago", days: 365 }
];

function formatDate(d: Date) {
	return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

function daysAgoDate(days: number) {
	const d = new Date();
	d.setDate(d.getDate() - days);
	return d;
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

function ProgressBar({ step, total = 3 }: { step: number; total?: number }) {
	// Show progress TO the current step, not through it
	// Step 1: ~10% (just started), Step 2: ~43%, Step 3: ~77%
	const progress = ((step - 1) / total) * 100 + 10;
	return (
		<div className="w-full mb-6">
			<div className="flex justify-between text-xs text-default-500 mb-2">
				<span>
					Step {step} of {total}
				</span>
			</div>
			<div className="w-full h-2 bg-default-200 rounded-full overflow-hidden">
				<div
					className="h-2 bg-primary rounded-full transition-all"
					style={{ width: `${Math.min(progress, 100)}%` }}
				/>
			</div>
		</div>
	);
}

// ─── Main content ─────────────────────────────────────────────────────────────

function OnboardingContent() {
	const router = useRouter();
	const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

	// Core state
	const [screen, setScreen] = useState<Screen>("loading");
	const [role, setRole] = useState<Role | null>(null);
	const [plan, setPlan] = useState<string>("free");
	const [userEmail, setUserEmail] = useState<string>("");
	const [syncEmail, setSyncEmail] = useState<string | null>(null);
	const [gmailError, setGmailError] = useState<string | null>(null);

	// Step 3 state
	const [selectedPreset, setSelectedPreset] = useState<string | null>(null);
	// Default to 30 days ago formatted as YYYY-MM-DD
	const [customDate, setCustomDate] = useState(() => {
		const date = new Date();
		date.setDate(date.getDate() - 30);
		return date.toISOString().split("T")[0];
	});
	const [coachEndDate, setCoachEndDate] = useState("");
	const [dateError, setDateError] = useState<string | null>(null);
	const [isSaving, setIsSaving] = useState(false);
	const [savedStartDate, setSavedStartDate] = useState<Date | null>(null);
	const [savedEndDate, setSavedEndDate] = useState<string>("");

	// Step 3.5 state (preview)
	const [previewEmails, setPreviewEmails] = useState<PreviewEmail[]>([]);
	const [previewTotalCount, setPreviewTotalCount] = useState(0);
	const [previewLimited, setPreviewLimited] = useState(false);
	const [isLoadingPreview, setIsLoadingPreview] = useState(false);
	const [previewError, setPreviewError] = useState<string | null>(null);

	// Step 4 state
	const [applicationsFound, setApplicationsFound] = useState(0);
	const [scanElapsed, setScanElapsed] = useState(0);
	const [scanFailed, setScanFailed] = useState(false);
	const [foundEmailsPreview, setFoundEmailsPreview] = useState<
		{ company_name: string; application_status: string }[]
	>([]);
	const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
	const elapsedRef = useRef<ReturnType<typeof setInterval> | null>(null);

	// ── Effective start date (computed from preset or custom) ─────────────────
	const effectiveStartDate: Date | null = (() => {
		if (selectedPreset) {
			const preset = PRESETS.find((p) => p.value === selectedPreset);
			if (preset) return daysAgoDate(preset.days);
		}
		if (customDate) return new Date(customDate + "T00:00:00");
		return null;
	})();

	const isOldDate = effectiveStartDate ? effectiveStartDate < daysAgoDate(30) : false;

	// ── Polling for scan status ───────────────────────────────────────────────
	const stopPolling = useCallback(() => {
		if (pollRef.current) clearInterval(pollRef.current);
		if (elapsedRef.current) clearInterval(elapsedRef.current);
	}, []);

	const startPolling = useCallback(
		(startDateForCheck: Date | null, currentRole: Role, currentPlan: string) => {
			setScanElapsed(0);
			setScanFailed(false);

			elapsedRef.current = setInterval(() => {
				setScanElapsed((s) => s + 1);
			}, 1000);

			pollRef.current = setInterval(async () => {
				try {
					const res = await fetch(`${apiUrl}/processing/status`, {
						credentials: "include"
					});
					if (!res.ok) return;
					const data = await res.json();
					const found = data.applications_found ?? 0;
					setApplicationsFound(found);

					if (data.status === "complete") {
						stopPolling();
						// Fetch email preview before transitioning
						if (found > 0) {
							try {
								const emailsRes = await fetch(`${apiUrl}/get-emails/preview`, {
									credentials: "include"
								});
								if (emailsRes.ok) {
									const emailsData = await emailsRes.json();
									setFoundEmailsPreview(emailsData.emails || []);
								}
							} catch {
								// Continue without preview if fetch fails
							}
						}
						if (found === 0) {
							setScreen("empty-state");
						} else if (currentRole === "jobseeker") {
							const withinWindow = startDateForCheck === null || startDateForCheck >= daysAgoDate(30);
							setScreen(withinWindow ? "step4a-i" : "step4a-ii");
						} else {
							setScreen(currentPlan === "promo" ? "step4b-i" : "step4b-ii");
						}
					}
				} catch {
					// network error — keep polling
				}
			}, 3000);
		},
		[apiUrl, stopPolling]
	);

	useEffect(() => () => stopPolling(), [stopPolling]);

	// ── Initialisation ───────────────────────────────────────────────────────
	useEffect(() => {
		const init = async () => {
			const isAuthenticated = await checkAuth(apiUrl);
			if (!isAuthenticated) {
				router.push("/login");
				return;
			}

			// Fetch login email and identify in PostHog
			try {
				const meRes = await fetch(`${apiUrl}/me`, { credentials: "include" });
				if (meRes.ok) {
					const me = await meRes.json();
					setUserEmail(me.email ?? me.user_email ?? "");
					if (me.user_id) posthog.identify(me.user_id, { email: me.email });
				}
			} catch {
				// non-blocking
			}

			// Check if returning from Gmail OAuth flow
			const gmailConnecting = localStorage.getItem("gmailConnecting");
			if (gmailConnecting) localStorage.removeItem("gmailConnecting");

			// Fetch onboarding status + processing status in parallel
			const [statusRes, processingRes] = await Promise.all([
				fetch(`${apiUrl}/api/users/onboarding-status`, { credentials: "include" }),
				fetch(`${apiUrl}/processing/status`, { credentials: "include" })
			]);

			if (!statusRes.ok) {
				router.push("/login");
				return;
			}

			const status = await statusRes.json();
			const processing = processingRes.ok ? await processingRes.json() : null;

			if (status.has_completed_onboarding) {
				router.replace("/dashboard");
				return;
			}

			const currentRole: Role = status.role && status.role !== "jobseeker" ? status.role : status.role || null;
			setRole(currentRole as Role | null);
			setPlan(status.plan ?? "free");
			setSyncEmail(status.sync_email_address ?? null);

			if (!status.role) {
				setScreen("step1");
				posthog.capture("onboarding_started");
				return;
			}

			if (!status.has_email_sync_configured) {
				// Show denial message if they just returned from a failed OAuth
				if (gmailConnecting) {
					setGmailError(
						"Gmail access is required to use JustAJobApp. We only read — never modify — your inbox."
					);
				}
				setScreen("step2");
				return;
			}

			// Gmail is connected — check if a scan is in progress or just finished
			if (processing && processing.status === "processing") {
				setScreen("step4-scanning");
				startPolling(null, currentRole as Role, status.plan ?? "free");
				return;
			}

			setScreen("step3");
		};

		init();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	// ── Handlers ─────────────────────────────────────────────────────────────

	const handleRoleSelect = async (selectedRole: Role) => {
		setRole(selectedRole);
		try {
			await fetch(`${apiUrl}/api/onboarding/role`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ role: selectedRole })
			});
		} catch {
			// non-blocking; role will be re-fetched on next page load
		}
		posthog.capture("onboarding_role_selected", { role: selectedRole });
		setScreen("step2");
	};

	const handleConnectGmail = () => {
		localStorage.setItem("gmailConnecting", "1");
		posthog.capture("gmail_connect_started", { role });
		window.location.href = `${apiUrl}/auth/google/email-sync`;
	};

	const handleStep3Submit = async () => {
		// Validate inputs
		if (!effectiveStartDate) {
			setDateError("Please select or enter a start date");
			return;
		}
		if (effectiveStartDate > new Date()) {
			setDateError("Start date can't be in the future");
			return;
		}
		if (role === "coach") {
			if (!coachEndDate) {
				setDateError("Please enter an end date");
				return;
			}
			if (new Date(coachEndDate) <= effectiveStartDate) {
				setDateError("End date must be after start date");
				return;
			}
		}
		setDateError(null);
		setIsLoadingPreview(true);
		setPreviewError(null);
		setSavedStartDate(effectiveStartDate);
		setSavedEndDate(coachEndDate);

		try {
			// Fetch email preview
			const startStr = effectiveStartDate.toISOString().split("T")[0].replace(/-/g, "/");
			const endStr = coachEndDate
				? new Date(coachEndDate).toISOString().split("T")[0].replace(/-/g, "/")
				: new Date().toISOString().split("T")[0].replace(/-/g, "/");

			const previewRes = await fetch(`${apiUrl}/api/emails/preview?start_date=${startStr}&end_date=${endStr}`, {
				credentials: "include"
			});

			if (!previewRes.ok) {
				const errorData = await previewRes.json().catch(() => ({}));
				if (errorData.detail === "token_expired") {
					setPreviewError("Gmail access expired. Please reconnect.");
				} else if (errorData.detail === "gmail_scope_missing") {
					setPreviewError("Gmail access required. Please reconnect.");
				} else {
					setPreviewError("Failed to fetch email preview. Please try again.");
				}
				return;
			}

			const previewData = await previewRes.json();
			setPreviewEmails(previewData.emails || []);
			setPreviewTotalCount(previewData.total_count || 0);
			setPreviewLimited(previewData.limited || false);

			posthog.capture("onboarding_preview_loaded", {
				role,
				email_count: previewData.total_count,
				limited: previewData.limited
			});

			setScreen("step3.5");
		} catch (err) {
			console.error("Preview fetch error:", err);
			setPreviewError("Something went wrong. Please try again.");
		} finally {
			setIsLoadingPreview(false);
		}
	};

	const handleConfirmScan = async () => {
		if (!savedStartDate) return;

		setIsSaving(true);

		try {
			// Trigger backfill via start-date
			const fetchOrder = role === "coach" ? "oldest_first" : "recent_first";
			// For free users selecting > 30 days, force to 1_month (30 days)
			const thirtyDaysAgo = daysAgoDate(30);
			const shouldCapTo30Days = plan === "free" && savedStartDate < thirtyDaysAgo;
			const effectivePreset = shouldCapTo30Days ? "1_month" : selectedPreset;
			const startDatePayload = effectivePreset
				? { preset: effectivePreset, fetch_order: fetchOrder, end_date: savedEndDate || null }
				: {
						preset: "custom",
						custom_date: savedStartDate.toISOString().split("T")[0],
						fetch_order: fetchOrder,
						end_date: savedEndDate || null
					};

			const sdRes = await fetch(`${apiUrl}/settings/start-date`, {
				method: "PUT",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(startDatePayload)
			});

			if (!sdRes.ok) {
				throw new Error("Failed to save start date");
			}

			posthog.capture("onboarding_scan_started", { role, plan });
			setScreen("step4-scanning");
			startPolling(savedStartDate, role!, plan);
		} catch (err) {
			console.error("Confirm scan error:", err);
			setDateError("Something went wrong. Please try again.");
		} finally {
			setIsSaving(false);
		}
	};

	const handleGoToDashboard = async () => {
		try {
			await fetch(`${apiUrl}/api/users/complete-onboarding`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" }
			});
		} catch {
			// non-blocking — onboarding_completed_at may already be set
		}
		posthog.capture("onboarding_completed", { role, plan });
		router.push("/dashboard");
	};

	const handleRetryGmail = () => {
		setGmailError(null);
		handleConnectGmail();
	};

	const handleRetryScan = async () => {
		setScanFailed(false);
		setScanElapsed(0);
		setScreen("step4-scanning");
		// Re-trigger via processing/start
		try {
			await fetch(`${apiUrl}/processing/start`, { method: "POST", credentials: "include" });
		} catch {
			// ignore
		}
		startPolling(savedStartDate, role!, plan);
	};

	const handleUpgrade = async () => {
		try {
			const res = await fetch(`${apiUrl}/payment/checkout`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ amount_cents: 500, trigger_type: "onboarding", is_recurring: true })
			});
			if (res.ok) {
				const data = await res.json();
				window.open(data.checkout_url, "_blank", "noopener,noreferrer");
			}
		} catch {
			// ignore
		}
	};

	// Switch role handler
	const handleSwitchRole = async () => {
		const newRole: Role = role === "jobseeker" ? "coach" : "jobseeker";
		try {
			await fetch(`${apiUrl}/api/onboarding/role`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ role: newRole })
			});
			setRole(newRole);
			posthog.capture("onboarding_role_switched", { from: role, to: newRole });
			// Reset date selections when switching roles
			setSelectedPreset(null);
			setCustomDate("");
			setCoachEndDate("");
			setDateError(null);
		} catch {
			// non-blocking
		}
	};

	// ── Today string for date picker max ─────────────────────────────────────
	const todayStr = new Date().toISOString().split("T")[0];
	const yesterdayStr = (() => {
		const d = new Date();
		d.setDate(d.getDate() - 1);
		return d.toISOString().split("T")[0];
	})();

	// ── Shared card wrapper ──────────────────────────────────────────────────
	const Card = ({ children }: { children: React.ReactNode }) => (
		<div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">{children}</div>
	);

	const pillClass = (active: boolean) =>
		`flex-1 py-2 px-3 rounded-lg border text-sm transition-colors cursor-pointer ${
			active
				? "border-blue-500 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium"
				: "border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500 text-gray-700 dark:text-gray-300"
		}`;

	// ── Screens ───────────────────────────────────────────────────────────────

	if (screen === "loading") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Spinner />
					<p className="mt-4 text-gray-600 dark:text-gray-300">Setting up your account…</p>
				</main>
			</>
		);
	}

	// Screen 1 — Role selection
	if (screen === "step1") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center px-4 py-8 sm:p-6">
					<div className="w-full max-w-md sm:max-w-lg">
						<h1 className="text-2xl sm:text-3xl font-bold text-foreground mb-8 sm:mb-10 text-center">
							How would you like to get started?
						</h1>
						<div className="flex flex-col gap-4 sm:gap-5">
							{/* Primary option - Job seeker */}
							<button
								className="group w-full p-4 sm:p-6 rounded-xl sm:rounded-2xl bg-primary border-2 border-dashed border-default-300 dark:border-default-400 hover:border-primary dark:hover:border-primary text-left transition-all"
								onClick={() => handleRoleSelect("jobseeker")}
							>
								<p className="font-semibold underline text-primary-foreground text-base sm:text-lg dark:text-default-600 mb-1 sm:mb-2">
									I&apos;m actively job searching
								</p>
								<p className="text-sm text-primary-foreground sm:text-base">
									Track applications from your inbox automatically
								</p>
							</button>
							{/* Secondary option - Coach */}
							<button
								className="group w-full p-4 sm:p-6 rounded-xl sm:rounded-2xl border-2 border-dashed border-default-300 dark:border-default-400 hover:border-primary dark:hover:border-primary text-left transition-all"
								onClick={() => handleRoleSelect("coach")}
							>
								<p className="font-semibold text-base sm:text-lg text-default-600 group-hover:text-foreground mb-1 sm:mb-2 transition-colors">
									I&apos;m a career coach
								</p>
								<p className="text-sm sm:text-base text-default-400 group-hover:text-default-600 transition-colors">
									See how accurately we detect job emails
								</p>
							</button>
						</div>
					</div>
				</main>
			</>
		);
	}

	// Screen 2 — Gmail consent (2A: job seeker / 2B: coach)
	if (screen === "step2") {
		const isCoach = role === "coach";
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={1} />
						<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
							{isCoach ? "Connect the Gmail from your past job search" : "Connect your inbox"}
						</h1>
						<p className="text-gray-500 dark:text-gray-400 text-sm mb-4">
							{isCoach
								? "Connect the specific Gmail account that has the job search emails you want to use."
								: "This is separate from signing in. We need permission to read the Gmail account where you receive job emails."}
						</p>

						{userEmail && (
							<p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
								You signed in with:{" "}
								<span className="font-medium text-gray-700 dark:text-gray-300">{userEmail}</span>
							</p>
						)}

						<div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4 text-sm text-blue-800 dark:text-blue-200">
							<p>
								{isCoach
									? "This can be a different Google account than the one you signed in with. If your old job search emails are in a different inbox, you can connect that one instead."
									: "Select the email you use for job applications — this may be different from the account you signed in with."}
							</p>
							<hr className="mt-4 mb-4 border-blue-200 dark:border-blue-700" />
							<p className="flex items-center gap-2">
								<span>🔒</span>
								<span>Read-only access — we can never send, delete, or modify your emails.</span>
							</p>
						</div>

						{gmailError && (
							<div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3 mb-4 text-sm text-red-700 dark:text-red-300">
								{gmailError}
							</div>
						)}

						<Button
							className="w-full bg-emerald-600 text-white hover:bg-emerald-700 mb-3"
							size="lg"
							startContent={<GoogleIcon size={18} />}
							onPress={gmailError ? handleRetryGmail : handleConnectGmail}
						>
							Connect Gmail
						</Button>

						{syncEmail && (
							<div className="mt-2 text-sm text-center">
								<span className="text-green-600 dark:text-green-400 font-medium">
									✓ Connected: {syncEmail}
								</span>
								<button className="ml-2 text-blue-500 underline text-xs" onClick={handleConnectGmail}>
									Not the right account? Connect a different one
								</button>
							</div>
						)}

						<div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 text-center">
							<button className="text-sm text-blue-500 hover:underline" onClick={handleSwitchRole}>
								Switch to {role === "jobseeker" ? "career coach" : "job seeker"}
							</button>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 3A (job seeker) / 3B (coach)
	if (screen === "step3") {
		const isCoach = role === "coach";
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={2} />
						<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
							{isCoach ? "Pick a date range from your past job search" : "Tell us about your job search"}
						</h1>
						<p className="text-gray-500 dark:text-gray-400 text-sm mb-5">
							{isCoach
								? "We'll scan this specific window so you can demo the app with your real data."
								: "When did you start looking?"}
						</p>

						{/* Quick-select pills */}
						<div className="flex gap-2 flex-wrap mb-4">
							{PRESETS.map((preset) => (
								<button
									key={preset.value}
									className={pillClass(selectedPreset === preset.value)}
									onClick={() => {
										setSelectedPreset(preset.value);
										setCustomDate("");
									}}
								>
									{preset.label}
								</button>
							))}
						</div>

						{/* Custom start date */}
						<div className="mb-4">
							<label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
								{isCoach ? "Or pick a specific start date" : "Or pick a date:"}
							</label>
							<input
								className="w-full px-3 py-2 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:border-blue-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
								max={isCoach ? yesterdayStr : todayStr}
								type="date"
								value={customDate}
								onChange={(e) => {
									setCustomDate(e.target.value);
									setSelectedPreset(null);
								}}
							/>
						</div>

						{/* Preview text */}
						{effectiveStartDate && (
							<p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
								{isCoach ? "Start: " : "We'll scan from "}
								<span className="font-medium text-gray-700 dark:text-gray-300">
									{formatDate(effectiveStartDate)}
								</span>
							</p>
						)}

						{/* Coach: end date */}
						{isCoach && (
							<div className="mb-4">
								<label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
									End date <span className="text-red-400">*</span>
								</label>
								<input
									className="w-full px-3 py-2 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:border-blue-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
									max={todayStr}
									min={
										effectiveStartDate ? effectiveStartDate.toISOString().split("T")[0] : undefined
									}
									type="date"
									value={coachEndDate}
									onChange={(e) => setCoachEndDate(e.target.value)}
								/>
								{effectiveStartDate && coachEndDate && (
									<p className="text-xs text-gray-400 mt-1">
										{(() => {
											const months = Math.round(
												(new Date(coachEndDate).getTime() - effectiveStartDate.getTime()) /
													(1000 * 60 * 60 * 24 * 30)
											);
											return `That's ~${months} month${months !== 1 ? "s" : ""} of emails`;
										})()}
									</p>
								)}
							</div>
						)}

						{/* Free user info for old start dates (job seeker) */}
						{!isCoach && isOldDate && (
							<div className="bg-amber-100 dark:bg-content2 dark:text-foreground border border-amber-300 dark:border-amber-700 rounded-lg p-3 mb-4 text-sm text-amber-900 dark:text-amber-100">
								Your dashboard shows the most recent 30 days. Your full history is always available via
								CSV export — the 30-day limit only applies to what&apos;s visible in the dashboard.
							</div>
						)}

						{dateError && <p className="text-sm text-red-500 mb-3">{dateError}</p>}
						{previewError && <p className="text-sm text-red-500 mb-3">{previewError}</p>}

						<Button
							className="w-full"
							color="primary"
							isLoading={isLoadingPreview}
							size="lg"
							onPress={handleStep3Submit}
						>
							Preview emails →
						</Button>

						<div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 text-center">
							<button className="text-sm text-blue-500 hover:underline" onClick={handleSwitchRole}>
								Switch to {role === "jobseeker" ? "career coach" : "job seeker"}
							</button>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 3.5 — Email Preview
	if (screen === "step3.5") {
		const thirtyDaysAgo = daysAgoDate(30);
		const showFreeTierNotice = plan === "free" && savedStartDate && savedStartDate < thirtyDaysAgo;

		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={2} total={3} />
						<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Preview your emails</h1>
						<p className="text-gray-500 dark:text-gray-400 text-sm mb-4">
							{previewTotalCount === 0
								? "No matching emails found in this date range."
								: `Found ${previewTotalCount} potential job-related email${previewTotalCount !== 1 ? "s" : ""}.`}
							{previewLimited && ` Showing first 15.`}
						</p>

						{/* Connected account with escape hatch */}
						<div className="flex justify-between items-center text-sm mb-3">
							<span className="text-gray-500 dark:text-gray-400">
								Connected as{" "}
								<span className="font-medium text-gray-700 dark:text-gray-300">{syncEmail}</span>
							</span>
							<button className="text-blue-500 hover:underline" onClick={handleConnectGmail}>
								Connect different account
							</button>
						</div>

						{/* Free tier notice - text link instead of button */}
						{showFreeTierNotice && (
							<div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3 mb-4 text-sm text-blue-800 dark:text-blue-200">
								<p>
									Your free plan processes the last 30 days through today ({formatDate(new Date())}).
									Emails before <strong>{formatDate(daysAgoDate(30))}</strong> may appear in this
									preview for your reference, but won&apos;t be processed in the app.{" "}
									<button className="underline hover:no-underline" onClick={handleUpgrade}>
										Upgrade for full history — $5/mo
									</button>
								</p>
							</div>
						)}

						{/* Sticky CTA above email list for free tier users */}
						{showFreeTierNotice && previewEmails.length > 0 && (
							<div className="mb-3">
								<Button
									className="w-full"
									color="primary"
									isLoading={isSaving}
									size="lg"
									onPress={handleConfirmScan}
								>
									Continue with last 30 days →
								</Button>
							</div>
						)}

						{/* Email list */}
						{previewEmails.length > 0 ? (
							<div className="max-h-64 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg mb-4">
								{previewEmails.map((email, idx) => (
									<div
										key={idx}
										className={`px-3 py-2 text-sm ${idx !== previewEmails.length - 1 ? "border-b border-gray-100 dark:border-gray-700" : ""}`}
									>
										<div className="flex justify-between items-start gap-2">
											<div className="min-w-0 flex-1">
												<p className="font-medium text-gray-900 dark:text-white truncate">
													{email.sender || email.sender_domain}
												</p>
												<p className="text-gray-600 dark:text-gray-400 truncate">
													{email.subject}
												</p>
											</div>
											<span className="text-xs text-gray-400 whitespace-nowrap">
												{email.date
													? new Date(email.date).toLocaleDateString("en-US", {
															month: "short",
															day: "numeric"
														})
													: ""}
											</span>
										</div>
									</div>
								))}
							</div>
						) : (
							<div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 mb-4 text-sm text-gray-600 dark:text-gray-400">
								<p className="font-medium mb-2">No emails found. This could mean:</p>
								<ul className="list-disc list-inside space-y-1">
									<li>Wrong Gmail account connected</li>
									<li>Date range doesn&apos;t include job-related emails</li>
									<li>Emails were deleted from Gmail</li>
								</ul>
							</div>
						)}

						{/* Actions */}
						<div className="space-y-2">
							{previewEmails.length > 0 && (
								<Button
									className="w-full"
									color="primary"
									isLoading={isSaving}
									size="lg"
									onPress={handleConfirmScan}
								>
									{showFreeTierNotice ? "Continue with last 30 days →" : "Process these emails →"}
								</Button>
							)}
							<button
								className="text-blue-500 hover:underline text-sm"
								onClick={() => setScreen("step3")}
							>
								← Change date range
							</button>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 4 — Scanning
	if (screen === "step4-scanning") {
		// Calculate actual scan range for display
		const thirtyDaysAgo = daysAgoDate(30);
		// Free users selecting > 30 days get capped to last 30 days
		const isFreeWithLimitedRange = plan === "free" && savedStartDate && savedStartDate < thirtyDaysAgo;
		const effectiveScanStart = isFreeWithLimitedRange ? thirtyDaysAgo : savedStartDate;
		const effectiveScanEnd = savedEndDate ? new Date(savedEndDate) : new Date();

		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={3} />
						<div className="text-center">
							<Spinner />
							<h1 className="text-xl font-bold text-gray-900 dark:text-white mt-4 mb-2">
								Scanning your inbox
							</h1>
							<p className="text-gray-500 dark:text-gray-400 text-sm mb-4">
								{scanElapsed > 60
									? "Still scanning — larger inboxes can take a couple of minutes"
									: "We're finding your job-related emails. This usually takes under 60 seconds."}
							</p>
							{effectiveScanStart && (
								<p className="text-sm text-gray-400 mb-4">
									Scanning from {formatDate(effectiveScanStart)} to {formatDate(effectiveScanEnd)}
								</p>
							)}
							{applicationsFound > 0 && (
								<p className="text-sm text-emerald-600 dark:text-emerald-400 font-medium">
									Found {applicationsFound} job-related email
									{applicationsFound !== 1 ? "s" : ""} so far…
								</p>
							)}
							{scanFailed && (
								<div className="mt-4 space-y-2">
									<p className="text-sm text-red-500">Something went wrong scanning your inbox.</p>
									<Button color="primary" size="sm" onPress={handleRetryScan}>
										Try again
									</Button>
									<Button
										className="ml-2"
										color="default"
										size="sm"
										variant="light"
										onPress={handleGoToDashboard}
									>
										Skip for now
									</Button>
								</div>
							)}
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 4A-i — Job seeker, within 30 days
	if (screen === "step4a-i") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={3} />
						<div className="text-center">
							<div className="text-4xl mb-3">✓</div>
							<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
								You&apos;re all set
							</h1>
							<p className="text-gray-500 dark:text-gray-400 text-sm mb-3">
								We found{" "}
								<span className="font-semibold text-gray-700 dark:text-gray-300">
									{applicationsFound} job-related email
									{applicationsFound !== 1 ? "s" : ""}
								</span>
							</p>
							{foundEmailsPreview.length > 0 && (
								<div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 mb-4 text-left">
									<ul className="space-y-2">
										{foundEmailsPreview.map((email, idx) => (
											<li key={idx} className="flex justify-between text-sm">
												<span className="text-gray-700 dark:text-gray-300 truncate mr-2">
													{email.company_name}
												</span>
												<span className="text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
													{email.application_status}
												</span>
											</li>
										))}
									</ul>
									{applicationsFound > foundEmailsPreview.length && (
										<p className="text-xs text-gray-400 mt-2 text-center">
											+{applicationsFound - foundEmailsPreview.length} more
										</p>
									)}
								</div>
							)}
							<p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
								Your entire search fits within your free window — nothing will be hidden.
							</p>
							<Button className="w-full" color="primary" size="lg" onPress={handleGoToDashboard}>
								Go to my dashboard →
							</Button>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 4A-ii — Job seeker, beyond 30 days
	if (screen === "step4a-ii") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={3} />
						<div className="text-center">
							<div className="text-4xl mb-3">✓</div>
							<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
								You&apos;re all set
							</h1>
							<p className="text-gray-500 dark:text-gray-400 text-sm mb-3">
								We found{" "}
								<span className="font-semibold text-gray-700 dark:text-gray-300">
									{applicationsFound} job-related email
									{applicationsFound !== 1 ? "s" : ""}
								</span>
							</p>
							{foundEmailsPreview.length > 0 && (
								<div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 mb-4 text-left">
									<ul className="space-y-2">
										{foundEmailsPreview.map((email, idx) => (
											<li key={idx} className="flex justify-between text-sm">
												<span className="text-gray-700 dark:text-gray-300 truncate mr-2">
													{email.company_name}
												</span>
												<span className="text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
													{email.application_status}
												</span>
											</li>
										))}
									</ul>
									{applicationsFound > foundEmailsPreview.length && (
										<p className="text-xs text-gray-400 mt-2 text-center">
											+{applicationsFound - foundEmailsPreview.length} more
										</p>
									)}
								</div>
							)}
							<div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3 mb-5 text-sm text-blue-800 dark:text-blue-200 text-left">
								Free accounts show the most recent 30 days in the dashboard. As your search continues,
								your view stays current — older entries roll out as new ones come in. Your full history
								is always exportable via CSV.
							</div>
							<Button className="w-full mb-3" color="primary" size="lg" onPress={handleGoToDashboard}>
								Go to my dashboard →
							</Button>
							<Button
								className="w-full mb-3"
								color="secondary"
								size="lg"
								variant="flat"
								onPress={handleUpgrade}
							>
								Upgrade to Premium — $5/mo
							</Button>
							<p className="text-xs text-gray-400">
								You can{" "}
								<button className="underline text-blue-500" onClick={handleGoToDashboard}>
									export all your data to CSV
								</button>{" "}
								at any time, for free.
							</p>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 4B-i — Coach, valid promo
	if (screen === "step4b-i") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={3} />
						<div className="text-center">
							<div className="text-4xl mb-3">✓</div>
							<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
								You&apos;re all set
							</h1>
							<p className="text-gray-500 dark:text-gray-400 text-sm mb-3">
								We found{" "}
								<span className="font-semibold text-gray-700 dark:text-gray-300">
									{applicationsFound} job-related email
									{applicationsFound !== 1 ? "s" : ""}
								</span>
								{savedStartDate && savedEndDate && (
									<>
										{" "}
										from{" "}
										<span className="font-medium">
											{formatDate(savedStartDate)} – {formatDate(new Date(savedEndDate))}
										</span>
									</>
								)}
							</p>
							{foundEmailsPreview.length > 0 && (
								<div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 mb-4 text-left">
									<ul className="space-y-2">
										{foundEmailsPreview.map((email, idx) => (
											<li key={idx} className="flex justify-between text-sm">
												<span className="text-gray-700 dark:text-gray-300 truncate mr-2">
													{email.company_name}
												</span>
												<span className="text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
													{email.application_status}
												</span>
											</li>
										))}
									</ul>
									{applicationsFound > foundEmailsPreview.length && (
										<p className="text-xs text-gray-400 mt-2 text-center">
											+{applicationsFound - foundEmailsPreview.length} more
										</p>
									)}
								</div>
							)}
							<p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
								You have full access to your selected date range — nothing is hidden.
							</p>
							<Button className="w-full" color="primary" size="lg" onPress={handleGoToDashboard}>
								Go to my dashboard →
							</Button>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Screen 4B-ii — Coach invitation screen (free coaches without promo)
	if (screen === "step4b-ii") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={3} />
						<div className="text-center">
							<div className="text-4xl mb-3">👋</div>
							<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
								Thanks for evaluating JustAJobApp
							</h1>
							<p className="text-gray-500 dark:text-gray-400 text-sm mb-3">
								We found{" "}
								<span className="font-semibold text-gray-700 dark:text-gray-300">
									{applicationsFound} job-related email
									{applicationsFound !== 1 ? "s" : ""}
								</span>{" "}
								in your preview.
							</p>
							{foundEmailsPreview.length > 0 && (
								<div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 mb-4 text-left">
									<ul className="space-y-2">
										{foundEmailsPreview.map((email, idx) => (
											<li key={idx} className="flex justify-between text-sm">
												<span className="text-gray-700 dark:text-gray-300 truncate mr-2">
													{email.company_name}
												</span>
												<span className="text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
													{email.application_status}
												</span>
											</li>
										))}
									</ul>
									{applicationsFound > foundEmailsPreview.length && (
										<p className="text-xs text-gray-400 mt-2 text-center">
											+{applicationsFound - foundEmailsPreview.length} more
										</p>
									)}
								</div>
							)}
							<div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-5 text-sm text-blue-800 dark:text-blue-200 text-left">
								<p className="font-medium mb-2">Ready to get coach access?</p>
								<p className="mb-3">
									Email{" "}
									<a
										className="font-medium underline"
										href="mailto:help@justajobapp.com?subject=Coach access request"
									>
										help@justajobapp.com
									</a>{" "}
									to request access. We&apos;ll set up your account and reply within 24 hours.
								</p>
								<p className="text-blue-700 dark:text-blue-300">
									Your account stays on the free plan until we activate coach access.
								</p>
							</div>
							<Button
								className="w-full mb-3"
								color="primary"
								size="lg"
								onPress={() =>
									window.open("mailto:help@justajobapp.com?subject=Coach access request", "_blank")
								}
							>
								Email help@justajobapp.com
							</Button>
							<p className="text-xs text-gray-400 mt-4">
								Want to track your own job search instead?{" "}
								<button className="underline text-blue-500" onClick={handleSwitchRole}>
									Switch to job seeker
								</button>
							</p>
						</div>
					</Card>
				</main>
			</>
		);
	}

	// Empty state — no emails found
	if (screen === "empty-state") {
		return (
			<>
				<Navbar />
				<main className="flex-grow flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
					<Card>
						<ProgressBar step={3} />
						<div className="text-center">
							<div className="text-4xl mb-3">📭</div>
							<h1 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
								We didn&apos;t find any job-related emails
							</h1>
							<ul className="text-sm text-gray-500 dark:text-gray-400 text-left space-y-2 mb-6 mt-4">
								<li>
									• Is this the right Gmail account? You connected{" "}
									<span className="font-medium text-gray-700 dark:text-gray-300">
										{syncEmail ?? "your Gmail"}
									</span>
									.
								</li>
								<li>• Try a wider date range — you can change this in Settings.</li>
								<li>
									• Your emails may use formats we don&apos;t recognise yet — you can add them
									manually from the dashboard.
								</li>
							</ul>
							<Button
								className="w-full mb-3"
								color="primary"
								size="lg"
								variant="flat"
								onPress={handleConnectGmail}
							>
								Connect a different Gmail account
							</Button>
							<Button
								className="w-full"
								color="default"
								size="lg"
								variant="light"
								onPress={handleGoToDashboard}
							>
								Go to dashboard anyway
							</Button>
						</div>
					</Card>
				</main>
			</>
		);
	}

	return null;
}

// ─── Page wrapper ──────────────────────────────────────────────────────────────

export default function OnboardingPage() {
	return (
		<div className="flex flex-col min-h-screen">
			<Suspense
				fallback={
					<>
						<Navbar />
						<main className="flex-grow flex items-center justify-center">
							<Spinner />
						</main>
					</>
				}
			>
				<OnboardingContent />
			</Suspense>
		</div>
	);
}
