"use client";
import { useState, useEffect, useMemo, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { addToast } from "@heroui/toast";
import { Modal, ModalContent, ModalBody } from "@heroui/react";
import React from "react";
import posthog from "posthog-js";

import JobApplicationsDashboard, { Application } from "@/components/JobApplicationsDashboard";
import SettingsModal from "@/components/SettingsModal";
import ProcessingBanner from "@/components/ProcessingBanner";
import ChangeStartDateModal from "@/components/ChangeStartDateModal";
import GoogleEmailSyncButton from "@/components/GoogleEmailSyncButton";
import StepUpAuthenticationPrompt from "@/components/StepUpAuthenticationDialog";
import { Navbar } from "@/components/navbar";
import { checkAuth } from "@/utils/auth";

// Processing status response type
interface ProcessingStatus {
	status: "idle" | "processing" | "complete";
	total_emails: number;
	processed_emails: number;
	applications_found: number;
	last_scan_at: string | null;
	should_rescan: boolean;
	scan_start_date: string | null;
	scan_end_date: string | null;
	stop_reason: "user_cancelled" | "rate_limited" | "monthly_cap" | "gmail_expired" | "error" | null;
}

export default function Dashboard() {
	const router = useRouter();
	const [data, setData] = useState<Application[]>([]);
	const [role, setRole] = useState<string>("jobseeker");
	const [clients, setClients] = useState<{ user_id: string; user_email: string }[]>([]);
	const [viewAs, setViewAs] = useState<string>("");
	const [loading, setLoading] = useState(true);
	const [downloading, setDownloading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	// Pagination States
	const [currentPage, setCurrentPage] = useState(1);
	const [totalPages, setTotalPages] = useState(1);
	const pageSize = 10;

	// Filter States
	const [searchTerm, setSearchTerm] = useState("");
	const [statusFilter, setStatusFilter] = useState("");
	const [companyFilter, setCompanyFilter] = useState("");
	const [hideRejections, setHideRejections] = useState<boolean>(true);
	const [hideApplicationConfirmations, setHideApplicationConfirmations] = useState<boolean>(false);

	// Premium status state
	const [showSettingsModal, setShowSettingsModal] = useState(false);
	const [isPremium, setIsPremium] = useState(false);
	const [scanEndDate, setScanEndDate] = useState<string | null>(null);
	const [monthlyEmailsUsed, setMonthlyEmailsUsed] = useState(0);
	const [monthlyEmailCap, setMonthlyEmailCap] = useState<number | null>(null);
	const [monthlyResetDate, setMonthlyResetDate] = useState<string | null>(null);

	// Free-tier hidden history state (US-004)
	const [hiddenEmailCount, setHiddenEmailCount] = useState(0);
	const [hiddenCutoffDate, setHiddenCutoffDate] = useState<string | null>(null);

	// Processing status state
	const [processingStatus, setProcessingStatus] = useState<ProcessingStatus | null>(null);
	const [refreshing, setRefreshing] = useState(false);
	const [cancelling, setCancelling] = useState(false);
	const [showSessionExpired, setShowSessionExpired] = useState(false);
	const [dismissedStopReason, setDismissedStopReason] = useState<string | null>(null);
	const [lastRefreshTime, setLastRefreshTime] = useState<number | null>(null);
	const [cooldownSeconds, setCooldownSeconds] = useState(0);
	const [initialized, setInitialized] = useState(false);

	// Start date state
	const [startDate, setStartDate] = useState<string | null>(null);
	const [showStartDateModal, setShowStartDateModal] = useState(false);
	const [updatingStartDate, setUpdatingStartDate] = useState(false);

	// Upgrade checkout state
	const [checkoutLoading, setCheckoutLoading] = useState(false);

	// Step-Up Auth state for sensitive actions (e.g., CSV download, Coach View-As)
	const [requiresStepUp, setRequiresStepUp] = useState(false);
	const [stepUpTrigger, setStepUpTrigger] = useState<"csv" | "coach" | null>(null);

	const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

	const searchParams = useSearchParams();

	// Filtering Logic: Processed client-side on the retrieved data
	const filteredData = useMemo(() => {
		return data.filter((item) => {
			const matchesSearch =
				!searchTerm ||
				item.company_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
				item.job_title.toLowerCase().includes(searchTerm.toLowerCase()) ||
				item.subject.toLowerCase().includes(searchTerm.toLowerCase());

			const matchesStatus = !statusFilter || item.application_status === statusFilter;
			const matchesCompany = !companyFilter || item.company_name === companyFilter;

			const isNotRejection = !hideRejections || !item.application_status.toLowerCase().includes("reject");

			const isNotApplicationConfirmation =
				!hideApplicationConfirmations ||
				!item.application_status.toLowerCase().includes("application confirmation");

			return matchesSearch && matchesStatus && matchesCompany && isNotRejection && isNotApplicationConfirmation;
		});
	}, [data, searchTerm, statusFilter, companyFilter, hideRejections, hideApplicationConfirmations]);

	// Fix for "1 of NaN": Dynamically compute total pages from filtered data
	const computedTotalPages = useMemo(() => {
		return Math.ceil(filteredData.length / pageSize) || 1;
	}, [filteredData.length]);

	// Fix for "Empty Page": Ensure the current page is always within the computed bounds
	const activePage = useMemo(() => {
		return Math.min(currentPage, Math.max(1, computedTotalPages));
	}, [currentPage, computedTotalPages]);

	// Format start date for display
	const formatStartDate = (isoString: string | null): string => {
		if (!isoString) return "Not set";
		return new Date(isoString).toLocaleDateString("en-US", {
			month: "short",
			day: "numeric",
			year: "numeric"
		});
	};

	// Format last synced time for display
	const formatLastSynced = (isoString: string | null): string => {
		if (!isoString) return "Never";
		const date = new Date(isoString);
		const now = new Date();
		const diffMs = now.getTime() - date.getTime();
		const diffHours = Math.floor(diffMs / (1000 * 60 * 60));

		if (diffHours < 1) return "Just now";
		if (diffHours === 1) return "1 hour ago";
		if (diffHours < 24) return `${diffHours} hours ago`;
		const diffDays = Math.floor(diffHours / 24);
		if (diffDays === 1) return "Yesterday";
		return `${diffDays} days ago`;
	};

	// Cooldown timer for manual refresh (60 seconds)
	useEffect(() => {
		if (!lastRefreshTime) return;

		const updateCooldown = () => {
			const elapsed = Math.floor((Date.now() - lastRefreshTime) / 1000);
			const remaining = Math.max(0, 60 - elapsed);
			setCooldownSeconds(remaining);

			if (remaining === 0) {
				setLastRefreshTime(null);
			}
		};

		updateCooldown();
		const interval = setInterval(updateCooldown, 1000);
		return () => clearInterval(interval);
	}, [lastRefreshTime]);

	// Handle upgrade checkout
	const handleUpgrade = async (triggerType = "dashboard") => {
		setCheckoutLoading(true);
		posthog.capture("upgrade_clicked", { trigger_type: triggerType });

		try {
			const response = await fetch(`${apiUrl}/payment/checkout`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					amount_cents: 500,
					trigger_type: triggerType,
					is_recurring: true
				})
			});

			if (response.ok) {
				const data = await response.json();
				window.open(data.checkout_url, "_blank", "noopener,noreferrer");
			} else {
				console.error("Failed to create checkout session");
			}
		} catch (error) {
			console.error("Upgrade error:", error);
		} finally {
			setCheckoutLoading(false);
		}
	};

	// Handle manual refresh
	const handleRefresh = async () => {
		if (refreshing || processingStatus?.status === "processing" || cooldownSeconds > 0) return;

		posthog.capture("manual_refresh_clicked");
		setRefreshing(true);
		setLastRefreshTime(Date.now());
		try {
			const response = await fetch(`${apiUrl}/processing/start`, {
				method: "POST",
				credentials: "include"
			});

			if (response.status === 401) {
				setShowSessionExpired(true);
				posthog.capture("session_expired_shown");
			} else if (response.status === 403) {
				const data = await response.json();
				if (data.detail === "gmail_scope_missing") {
					setShowSessionExpired(true);
					posthog.capture("gmail_scope_missing_shown");
				}
			} else if (response.status === 409) {
				addToast({
					title: "Scan already in progress",
					color: "primary"
				});
			} else if (response.ok) {
				const statusResponse = await fetch(`${apiUrl}/processing/status`, {
					method: "GET",
					credentials: "include"
				});
				if (statusResponse.ok) {
					const statusData = await statusResponse.json();
					setProcessingStatus(statusData);
				}
			}
		} catch (error) {
			console.error("Error starting refresh:", error);
			addToast({
				title: "Failed to start refresh",
				description: "Please try again",
				color: "danger"
			});
		} finally {
			setRefreshing(false);
		}
	};

	// Handle cancel scan
	const handleCancelScan = async () => {
		if (cancelling || processingStatus?.status !== "processing") return;

		posthog.capture("scan_cancel_clicked");
		setCancelling(true);
		try {
			const response = await fetch(`${apiUrl}/processing/cancel`, {
				method: "POST",
				credentials: "include"
			});

			if (response.ok) {
				addToast({
					title: "Scan cancelled",
					color: "primary"
				});
				// Refresh status to update UI
				const statusResponse = await fetch(`${apiUrl}/processing/status`, {
					method: "GET",
					credentials: "include"
				});
				if (statusResponse.ok) {
					const statusData = await statusResponse.json();
					setProcessingStatus(statusData);
				}
				// Refresh emails to show any found before cancellation
				await fetchData();
			} else if (response.status === 404) {
				addToast({
					title: "No scan in progress",
					color: "warning"
				});
			}
		} catch (error) {
			console.error("Error cancelling scan:", error);
			addToast({
				title: "Failed to cancel scan",
				description: "Please try again",
				color: "danger"
			});
		} finally {
			setCancelling(false);
		}
	};

	// Identify user in PostHog once on mount
	useEffect(() => {
		const identifyUser = async () => {
			try {
				const isAuthenticated = await checkAuth(apiUrl);
				if (!isAuthenticated) return;

				const userResponse = await fetch(`${apiUrl}/me`, {
					method: "GET",
					credentials: "include"
				});
				if (userResponse.ok) {
					const userData = await userResponse.json();
					if (userData.user_id && typeof posthog !== "undefined" && typeof posthog.identify === "function") {
						posthog.identify(userData.user_id, { email: userData.email });
					}
				}
			} catch (error) {
				/* Silently fail PostHog identification */
			}
		};
		identifyUser();
		posthog.capture("dashboard_viewed");
	}, [apiUrl]);

	// Fetch start date on mount
	useEffect(() => {
		const fetchStartDate = async () => {
			try {
				const response = await fetch(`${apiUrl}/settings/start-date`, {
					method: "GET",
					credentials: "include"
				});
				if (response.ok) {
					const data = await response.json();
					setStartDate(data.start_date);
				}
			} catch (error) {
				console.error("Error fetching start date:", error);
			}
		};
		fetchStartDate();
	}, [apiUrl]);

	// Handle start date update
	const handleStartDateSave = async (data: {
		preset: string;
		custom_date?: string;
		fetch_order: string;
		end_date: string | null;
	}) => {
		setUpdatingStartDate(true);
		posthog.capture("start_date_changed", { preset: data.preset });

		try {
			const response = await fetch(`${apiUrl}/settings/start-date`, {
				method: "PUT",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(data)
			});

			if (response.status === 401) {
				setShowStartDateModal(false);
				setShowSessionExpired(true);
				posthog.capture("session_expired_shown");
			} else if (response.ok) {
				const result = await response.json();
				setStartDate(result.start_date);
				setShowStartDateModal(false);

				if (result.rescan_started) {
					const statusResponse = await fetch(`${apiUrl}/processing/status`, {
						method: "GET",
						credentials: "include"
					});
					if (statusResponse.ok) {
						const statusData = await statusResponse.json();
						setProcessingStatus(statusData);
					}
				}

				addToast({
					title: "Start date updated",
					description: result.rescan_started ? "Rescanning your inbox..." : "Start date saved",
					color: "success"
				});
			} else {
				throw new Error("Failed to update start date");
			}
		} catch (error) {
			console.error("Error updating start date:", error);
			addToast({
				title: "Failed to update start date",
				description: "Please try again",
				color: "danger"
			});
		} finally {
			setUpdatingStartDate(false);
		}
	};

	const fetchProcessingStatus = React.useCallback(async () => {
		try {
			const response = await fetch(`${apiUrl}/processing/status`, {
				method: "GET",
				credentials: "include"
			});
			if (response.ok) {
				const data = await response.json();
				setProcessingStatus(data);
			}
		} catch (error) {
			console.error("Error fetching processing status:", error);
		}
	}, [apiUrl]);

	useEffect(() => {
		fetchProcessingStatus();
	}, [fetchProcessingStatus]);

	useEffect(() => {
		if (processingStatus?.status !== "processing") return;
		const interval = setInterval(fetchProcessingStatus, 5000);
		return () => clearInterval(interval);
	}, [processingStatus?.status, fetchProcessingStatus]);

	const prevProcessingStatus = React.useRef<string | undefined>();
	useEffect(() => {
		if (prevProcessingStatus.current === "processing" && processingStatus?.status !== "processing") {
			fetchData();
		}
		prevProcessingStatus.current = processingStatus?.status;
	}, [processingStatus?.status]);

	const fetchPremiumStatus = useCallback(async () => {
		try {
			const response = await fetch(`${apiUrl}/settings/premium-status`, {
				method: "GET",
				credentials: "include"
			});

			if (response.ok) {
				const data = await response.json();
				setIsPremium(data.is_premium);
				setMonthlyEmailsUsed(data.emails_processed_this_month ?? 0);
				setMonthlyEmailCap(data.monthly_email_cap ?? null);
				setMonthlyResetDate(data.monthly_reset_date ?? null);
				setScanEndDate(data.scan_end_date ?? null);
			}
		} catch (error) {
			console.error("Error fetching premium status:", error);
		}
	}, [apiUrl]);

	useEffect(() => {
		fetchPremiumStatus();
	}, [fetchPremiumStatus]);

	const fetchData = async () => {
		try {
			setLoading(true);
			const isAuthenticated = await checkAuth(apiUrl);
			if (!isAuthenticated) {
				addToast({
					title: "Session expired. Please sign in again.",
					color: "warning"
				});
				router.push("/login?reconnect=true");
				return;
			}

			const onboardingResp = await fetch(`${apiUrl}/api/users/onboarding-status`, {
				credentials: "include"
			});
			if (onboardingResp.ok) {
				const data = await onboardingResp.json();
				if (!data.has_completed_onboarding) {
					router.replace("/onboarding");
					return;
				}
				if (!data.has_email_sync_configured) {
					router.replace("/email-sync-setup");
					return;
				}
			}

			const headers: HeadersInit = {};
			if (viewAs) {
				headers["X-View-As"] = viewAs;
			}

			// We fetch the full list here to allow client-side filtering/searching across the whole set.
			const response = await fetch(`${apiUrl}/get-emails`, {
				method: "GET",
				credentials: "include",
				headers
			});

			if (!response.ok) {
				// 1. Check if the backend is requesting a Step-Up Authentication (e.g. for a Coach)
				if (response.status === 403 && response.headers.get("X-Step-Up-Auth") === "true") {
					setStepUpTrigger("coach");
					setRequiresStepUp(true);
					setLoading(false);
					return;
				}

				if (response.status === 403) {
					const onboardingRequired = response.headers.get("X-Onboarding-Required");
					if (onboardingRequired === "true") {
						router.replace("/onboarding");
						return;
					}
				}
				if (response.status === 404) {
					setError("No applications found");
				} else {
					throw new Error(`HTTP error! status: ${response.status}`);
				}
			}

			const result = await response.json();
			// Backend usually returns a list, if it returns an object with totalPages, we can use that as fallback
			if (result.totalPages) setTotalPages(result.totalPages);

			setData(Array.isArray(result) ? result : result.data || []);

			// Fetch count of emails hidden behind the free-tier 30-day window (US-004)
			try {
				const hiddenResp = await fetch(`${apiUrl}/emails/hidden-count`, {
					method: "GET",
					credentials: "include",
					headers
				});
				if (hiddenResp.ok) {
					const hiddenData = await hiddenResp.json();
					setHiddenEmailCount(hiddenData.hidden_count ?? 0);
					setHiddenCutoffDate(hiddenData.cutoff_date ?? null);
				}
			} catch {
				// non-critical; ignore
			}
		} catch {
			setError("Failed to load applications");
		} finally {
			setLoading(false);
		}
	};

	// Wrap downloadCsv in useCallback to stabilize its reference
	const downloadCsv = useCallback(async () => {
		setDownloading(true);
		posthog.capture("csv_export_clicked", { application_count: data.length });
		try {
			const response = await fetch(`${apiUrl}/process-csv`, {
				method: "GET",
				credentials: "include"
			});

			const requiresStepUpHeader = response.headers.get("X-Step-Up-Auth");
			if (requiresStepUpHeader === "true" && response.status === 403) {
				setStepUpTrigger("csv");
				setRequiresStepUp(true);
				return;
			}

			if (!response.ok) {
				let description = "Something went wrong. Please try again.";
				if (response.status === 429) {
					description = "Download limit reached. Please wait before trying again.";
				} else {
					description = "Please try again or contact help@justajobapp.com if the issue persists.";
				}
				addToast({
					title: "Failed to download CSV",
					description,
					color: "danger"
				});
				return;
			}

			posthog.capture("csv_export_completed", { application_count: data.length });
			const blob = await response.blob();
			const link = document.createElement("a");
			const url = URL.createObjectURL(blob);
			link.href = url;
			link.download = `job_applications_${new Date().toISOString().split("T")[0]}.csv`;
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
			URL.revokeObjectURL(url);
		} catch {
			addToast({
				title: "Something went wrong",
				description: "Please try again",
				color: "danger"
			});
		} finally {
			setDownloading(false);
		}
	}, [apiUrl, data.length]);

	// --- Handle return actions from Step-Up Auth flows ---
	useEffect(() => {
		const action = searchParams.get("action");
		if (action === "csv_export") {
			// Automatically resume the CSV download
			window.history.replaceState({}, "", window.location.pathname);
			downloadCsv();
		} else if (action === "view_as") {
			// Automatically resume viewing as a specific client
			const clientId = searchParams.get("client_id");
			if (clientId) {
				setViewAs(clientId);
				window.history.replaceState({}, "", window.location.pathname);
			}
		}
	}, [searchParams, downloadCsv]);

	// Initialize role and coach clients before fetching data
	useEffect(() => {
		const init = async () => {
			try {
				const meResp = await fetch(`${apiUrl}/me`, { method: "GET", credentials: "include" });
				if (meResp.ok) {
					const meData = await meResp.json();
					if (meData.role) {
						setRole(meData.role);
						if (meData.role === "coach") {
							const clientsResp = await fetch(`${apiUrl}/coach/clients`, {
								method: "GET",
								credentials: "include"
							});
							if (clientsResp.ok) {
								const list = await clientsResp.json();
								setClients(list);
								if (list.length > 0) {
									setViewAs(list[0].user_id);
								}
							}
						}
					}
				}
			} catch {
				/*ignore*/
			}
			setInitialized(true);
		};
		init();
	}, [apiUrl]);

	// Fetch data only after initialization is complete
	useEffect(() => {
		if (initialized) {
			fetchData();
		}
	}, [initialized, viewAs]);

	const nextPage = () => {
		if (currentPage < computedTotalPages) {
			setCurrentPage(currentPage + 1);
		}
	};

	const prevPage = () => {
		if (currentPage > 1) {
			setCurrentPage(currentPage - 1);
		}
	};

	const handleRemoveItem = async (id: string) => {
		try {
			const response = await fetch(`${apiUrl}/delete-email/${id}`, {
				method: "DELETE",
				credentials: "include"
			});
			if (!response.ok) throw new Error("Failed to delete the item");

			setData((prevData) => prevData.filter((item) => item.id !== id));
			addToast({ title: "Item removed successfully", color: "success" });
		} catch (error) {
			addToast({
				title: "Failed to remove item",
				description: "Please try again or contact support.",
				color: "danger"
			});
		}
	};

	if (error) {
		return (
			<div className="p-6 flex flex-col items-center justify-center min-h-[50vh]">
				<p className="text-red-600 mb-4">{error}</p>
				<button className="px-4 py-2 bg-blue-600 text-white rounded" onClick={() => window.location.reload()}>
					Retry
				</button>
			</div>
		);
	}

	return (
		<>
			<Navbar isPremium={isPremium} onSettingsClick={() => setShowSettingsModal(true)} />

			{processingStatus?.status === "processing" && (
				<ProcessingBanner
					cancelling={cancelling}
					found={processingStatus.applications_found}
					processed={processingStatus.processed_emails}
					scanEndDate={processingStatus.scan_end_date}
					scanStartDate={processingStatus.scan_start_date}
					total={processingStatus.total_emails}
					onCancel={handleCancelScan}
				/>
			)}

			{/* Return-after-incomplete banners */}
			{processingStatus?.status !== "processing" &&
				processingStatus?.stop_reason &&
				dismissedStopReason !== processingStatus.stop_reason && (
					<div
						className={`mx-6 mt-4 p-4 rounded-lg border flex items-start justify-between ${
							processingStatus.stop_reason === "monthly_cap" ||
							processingStatus.stop_reason === "user_cancelled"
								? "bg-red-50 dark:bg-red-900 border-red-200 dark:border-red-800"
								: processingStatus.stop_reason === "error" ||
									  processingStatus.stop_reason === "gmail_expired"
									? "bg-red-50 dark:bg-red-900 border-red-200 dark:border-red-800"
									: "bg-amber-50 dark:bg-amber-900 border-amber-200 dark:border-amber-800"
						}`}
					>
						<div className="flex-1">
							<p
								className={`text-sm font-medium ${
									processingStatus.stop_reason === "monthly_cap" ||
									processingStatus.stop_reason === "error" ||
									processingStatus.stop_reason === "gmail_expired"
										? "text-red-800 dark:text-red-200"
										: "text-amber-800 dark:text-amber-200"
								}`}
							>
								{processingStatus.stop_reason === "user_cancelled" &&
									"Your last scan was cancelled. Emails found before stopping are shown."}
								{processingStatus.stop_reason === "rate_limited" &&
									"Gmail rate limit hit. Scan will auto-resume shortly."}
								{processingStatus.stop_reason === "monthly_cap" &&
									`Monthly limit reached. Resets ${monthlyResetDate ? new Date(monthlyResetDate).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : "on the 1st"}.`}
								{processingStatus.stop_reason === "gmail_expired" && "Gmail access expired."}
								{processingStatus.stop_reason === "error" &&
									"Something went wrong during your last scan."}
							</p>
							<div className="mt-2 flex gap-2">
								{processingStatus.stop_reason === "user_cancelled" && (
									<button
										className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
										onClick={handleRefresh}
									>
										Resume scan
									</button>
								)}
								{processingStatus.stop_reason === "monthly_cap" && !isPremium && (
									<button
										className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
										onClick={() => handleUpgrade("monthly_cap_banner")}
									>
										Upgrade for 5,000 emails/month
									</button>
								)}
								{processingStatus.stop_reason === "gmail_expired" && (
									<a
										className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
										href={`${apiUrl}/auth/google/email-sync`}
									>
										Reconnect Gmail
									</a>
								)}
								{processingStatus.stop_reason === "error" && (
									<button
										className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
										onClick={handleRefresh}
									>
										Try again
									</button>
								)}
							</div>
						</div>
						<button
							className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 ml-2"
							onClick={() => setDismissedStopReason(processingStatus.stop_reason)}
						>
							<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path
									d="M6 18L18 6M6 6l12 12"
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
								/>
							</svg>
						</button>
					</div>
				)}

			<div className="flex items-center justify-between px-6 pt-4">
				<p className="text-sm text-gray-500 dark:text-gray-400">
					Tracking since {formatStartDate(startDate)}
					<button
						className="ml-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50"
						disabled={processingStatus?.status === "processing"}
						title={isPremium ? "Edit start date" : "Unlock full history"}
						onClick={() => {
							posthog.capture("start_date_edit_opened", { is_premium: isPremium });
							setShowStartDateModal(true);
						}}
					>
						{isPremium ? (
							<svg className="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path
									d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
								/>
							</svg>
						) : (
							<svg className="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path
									d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
								/>
							</svg>
						)}
					</button>
					<span className="mx-2">•</span>
					{processingStatus?.status === "processing"
						? "Scanning now..."
						: `Last synced: ${formatLastSynced(processingStatus?.last_scan_at || null)}`}
				</p>
				<button
					className="flex items-center gap-2 px-3 py-1.5 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded border border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700"
					disabled={refreshing || processingStatus?.status === "processing" || cooldownSeconds > 0}
					title={
						processingStatus?.status === "processing"
							? "Refresh available after scan completes"
							: cooldownSeconds > 0
								? `Last refreshed ${cooldownSeconds}s ago`
								: undefined
					}
					onClick={handleRefresh}
				>
					<svg
						className={`w-4 h-4 ${processingStatus?.status === "processing" || refreshing ? "animate-spin" : ""}`}
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
						/>
					</svg>
					{cooldownSeconds > 0 ? `${cooldownSeconds}s` : "Refresh"}
				</button>
			</div>

			{role === "coach" && clients.length > 0 && (
				<div className="mb-4 p-4 rounded bg-gray-100 dark:bg-gray-800" data-testid="coach-view-as-container">
					<label className="mr-2 font-medium">View as:</label>
					<select
						className="px-2 py-1 rounded bg-white dark:bg-black border border-gray-300 dark:border-gray-600"
						data-testid="coach-view-as-select"
						value={viewAs}
						onChange={(e) => {
							setViewAs(e.target.value);
							setCurrentPage(1);
						}}
					>
						<option value="">Me (Coach)</option>
						{clients.map((c) => (
							<option key={c.user_id} value={c.user_id}>
								{c.user_email}
							</option>
						))}
					</select>
				</div>
			)}

			{monthlyEmailCap !== null && monthlyEmailsUsed >= monthlyEmailCap && monthlyResetDate && (
				<div className="mx-6 mb-4 px-4 py-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 flex flex-col sm:flex-row items-start sm:items-center gap-3">
					<div className="flex-1 text-sm text-red-800 dark:text-red-300">
						{"You've reached your monthly limit — resets on "}
						<span className="font-medium">
							{new Date(monthlyResetDate).toLocaleDateString("en-US", { month: "long", day: "numeric" })}
						</span>
						{isPremium ? (
							"."
						) : (
							<>
								{", or "}
								<button
									className="underline font-medium"
									onClick={() => handleUpgrade("cap_reached_banner")}
								>
									upgrade to Pro
								</button>
								{" for a higher limit."}
							</>
						)}
					</div>
				</div>
			)}

			{hiddenEmailCount > 0 && hiddenCutoffDate && !isPremium && (
				<div className="mx-6 mb-4 mt-4 px-4 py-3 rounded-lg bg-content1 border border-blue-200 dark:border-blue-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
					<div>
						<p className="text-sm text-foreground">
							{hiddenEmailCount} older email{hiddenEmailCount === 1 ? " isn't" : "s aren't"} shown on your
							free plan.
						</p>
						<p className="text-sm text-foreground-500">
							They&apos;re still yours —{" "}
							<button className="text-blue-600 dark:text-blue-400 hover:underline" onClick={downloadCsv}>
								export everything to CSV
							</button>
							.
						</p>
					</div>
					<button
						className="shrink-0 px-4 py-2 text-sm font-medium rounded-lg transition-colors"
						style={{ backgroundColor: "#f59e0b", color: "#1f2937" }}
						onClick={() => handleUpgrade("hidden_emails_banner")}
					>
						Upgrade — $5/mo
					</button>
				</div>
			)}

			{/* Cap-reached banner */}
			{monthlyEmailCap && monthlyEmailsUsed >= monthlyEmailCap && processingStatus?.status !== "processing" && (
				<div className="mx-6 mb-4 px-4 py-4 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 flex flex-col sm:flex-row items-start sm:items-center gap-3">
					<div className="flex-1">
						<p className="text-sm font-medium text-red-800 dark:text-red-200">
							You&apos;ve processed {monthlyEmailsUsed.toLocaleString()} of{" "}
							{monthlyEmailCap.toLocaleString()} emails this month.
						</p>
						<p className="text-sm text-red-700 dark:text-red-300 mt-1">
							Resets{" "}
							{monthlyResetDate
								? new Date(monthlyResetDate).toLocaleDateString("en-US", {
										month: "short",
										day: "numeric"
									})
								: "on the 1st"}
							.
						</p>
					</div>
					{!isPremium && (
						<button
							className="shrink-0 inline-flex items-center px-4 py-2 rounded-md bg-red-600 hover:bg-red-700 text-white text-sm font-medium transition-colors"
							onClick={() => handleUpgrade("cap_reached_banner")}
						>
							Upgrade for 5,000 emails/month
						</button>
					)}
				</div>
			)}

			<JobApplicationsDashboard
				companyFilter={companyFilter}
				currentPage={activePage} // Fix: Uses reactive activePage
				data={filteredData}
				downloading={downloading}
				hideApplicationConfirmations={hideApplicationConfirmations}
				hideRejections={hideRejections}
				isScanning={processingStatus?.status === "processing"}
				loading={loading}
				readOnly={!!viewAs}
				searchTerm={searchTerm}
				statusFilter={statusFilter}
				totalPages={computedTotalPages} // Fix: Uses reactive computedTotalPages
				onCompanyFilterChange={(v) => {
					setCompanyFilter(v);
					setCurrentPage(1);
				}}
				onDownloadCsv={downloadCsv}
				onHideApplicationConfirmationsChange={(v) => {
					setHideApplicationConfirmations(v);
					setCurrentPage(1);
				}}
				onHideRejectionsChange={(v) => {
					setHideRejections(v);
					setCurrentPage(1);
				}}
				onNextPage={nextPage}
				onPrevPage={prevPage}
				onRefreshData={fetchData}
				onRemoveItem={handleRemoveItem}
				onSearchChange={(v) => {
					setSearchTerm(v);
					setCurrentPage(1);
				}}
				onStatusFilterChange={(v) => {
					setStatusFilter(v);
					setCurrentPage(1);
				}}
			/>

			{/* Sensitive Action Step-Up Modal */}
			<Modal isOpen={requiresStepUp} size="md" onClose={() => setRequiresStepUp(false)}>
				<ModalContent className="dark:bg-[#1a2e1a]">
					<ModalBody>
						{stepUpTrigger === "csv" ? (
							<StepUpAuthenticationPrompt
								actionText="download your data export"
								returnUrl="/dashboard?action=csv_export"
								onCancel={() => setRequiresStepUp(false)}
							/>
						) : (
							<StepUpAuthenticationPrompt
								actionText="view client data as a coach"
								returnUrl={`/dashboard?action=view_as&client_id=${viewAs}`}
								onCancel={() => {
									setRequiresStepUp(false);
									setViewAs(""); // Reset to coach's own view if cancelled
								}}
							/>
						)}
					</ModalBody>
				</ModalContent>
			</Modal>

			<SettingsModal
				isOpen={showSettingsModal}
				onClose={() => setShowSettingsModal(false)}
				onSubscriptionChange={() => {
					fetchPremiumStatus();
				}}
			/>

			{showSessionExpired && (
				<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
					<div className="bg-white dark:bg-gray-800 rounded-lg max-w-sm w-full mx-4 p-6">
						<h2 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white text-center">
							Reconnect to refresh
						</h2>
						<p className="text-gray-600 dark:text-gray-300 mb-6 text-center">
							Your existing data is still available. Sign in again to scan for new applications.
						</p>
						<div onClick={() => posthog.capture("token_expired_reauth")}>
							<GoogleEmailSyncButton />
						</div>
						<button
							className="w-full mt-3 py-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 text-sm"
							onClick={() => setShowSessionExpired(false)}
						>
							Cancel
						</button>
					</div>
				</div>
			)}

			<ChangeStartDateModal
				currentDate={startDate}
				isLoading={updatingStartDate}
				isOpen={showStartDateModal}
				isPremium={isPremium}
				onClose={() => setShowStartDateModal(false)}
				onSave={handleStartDateSave}
				onUpgrade={() => handleUpgrade("start_date_modal")}
			/>
		</>
	);
}
