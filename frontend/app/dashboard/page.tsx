"use client";
import { useState, useEffect, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import { addToast } from "@heroui/toast";
import React from "react";
import posthog from "posthog-js";

import JobApplicationsDashboard, { Application } from "@/components/JobApplicationsDashboard";
import ContributorBadge from "@/components/ContributorBadge";
import SettingsModal from "@/components/SettingsModal";
import ProcessingBanner from "@/components/ProcessingBanner";
import ChangeStartDateModal from "@/components/ChangeStartDateModal";
import GoogleEmailSyncButton from "@/components/GoogleEmailSyncButton";
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
	const [currentPage, setCurrentPage] = useState(1);
	const [totalPages, setTotalPages] = useState(1);
	const [searchTerm, setSearchTerm] = useState("");
	const [statusFilter, setStatusFilter] = useState("");
	const [companyFilter, setCompanyFilter] = useState("");
	const [hideRejections, setHideRejections] = useState<boolean>(true);
	const [hideApplicationConfirmations, setHideApplicationConfirmations] = useState<boolean>(false);
	const [normalizedJobTitleFilter, setNormalizedJobTitleFilter] = useState("");

	// Premium status state
	const [contributionCents, setContributionCents] = useState(0);
	const [showSettingsModal, setShowSettingsModal] = useState(false);
	const [isPremium, setIsPremium] = useState(false);

	// Processing status state
	const [processingStatus, setProcessingStatus] = useState<ProcessingStatus | null>(null);
	const [refreshing, setRefreshing] = useState(false);
	const [showSessionExpired, setShowSessionExpired] = useState(false);
	const [autoRescanTriggered, setAutoRescanTriggered] = useState(false);

	// Start date state
	const [startDate, setStartDate] = useState<string | null>(null);
	const [showStartDateModal, setShowStartDateModal] = useState(false);
	const [updatingStartDate, setUpdatingStartDate] = useState(false);

	const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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

	// Handle manual refresh
	const handleRefresh = async () => {
		if (refreshing || processingStatus?.status === "processing") return;

		posthog.capture("manual_refresh_clicked");
		setRefreshing(true);
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
					// User needs to re-auth with Gmail scope - show the reconnect modal
					// They can still view their existing data
					setShowSessionExpired(true);
					posthog.capture("gmail_scope_missing_shown");
				}
			} else if (response.status === 409) {
				// Already processing, just refresh status
				addToast({
					title: "Scan already in progress",
					color: "primary"
				});
			} else if (response.ok) {
				// Refresh the status to pick up the new processing state
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
				// Silently fail PostHog identification - don't block the dashboard
			}
		};
		identifyUser();

		// Track dashboard view
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
	const handleStartDateSave = async (data: { preset: string; custom_date?: string }) => {
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
					// Refresh processing status to pick up the new scan
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

	// Fetch processing status on mount
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

	// Initial fetch on mount
	useEffect(() => {
		fetchProcessingStatus();
	}, [fetchProcessingStatus]);

	// Poll processing status only while processing is active
	useEffect(() => {
		if (processingStatus?.status !== "processing") return;

		const interval = setInterval(fetchProcessingStatus, 5000);
		return () => clearInterval(interval);
	}, [processingStatus?.status, fetchProcessingStatus]);

	// Refresh applications once when processing completes
	const prevProcessingStatus = React.useRef<string | undefined>();
	useEffect(() => {
		// Detect transition from "processing" to another status
		if (prevProcessingStatus.current === "processing" && processingStatus?.status !== "processing") {
			fetchData();
		}
		prevProcessingStatus.current = processingStatus?.status;
	}, [processingStatus?.status]);

	// Auto-trigger rescan if >24 hours since last scan
	useEffect(() => {
		if (
			processingStatus?.should_rescan &&
			processingStatus?.status !== "processing" &&
			!autoRescanTriggered &&
			!refreshing
		) {
			setAutoRescanTriggered(true);
			posthog.capture("auto_rescan_triggered");
			handleRefresh();
		}
	}, [processingStatus?.should_rescan, processingStatus?.status, autoRescanTriggered, refreshing]);

	// Fetch premium status for navbar and settings
	const fetchPremiumStatus = useCallback(async () => {
		try {
			const response = await fetch(`${apiUrl}/settings/premium-status`, {
				method: "GET",
				credentials: "include"
			});

			if (response.ok) {
				const data = await response.json();
				setIsPremium(data.is_premium);
				setContributionCents(data.monthly_contribution_cents || 0);
			}
		} catch (error) {
			console.error("Error fetching premium status:", error);
		}
	}, [apiUrl]);

	// Fetch premium status on mount
	useEffect(() => {
		fetchPremiumStatus();
	}, [fetchPremiumStatus]);

	const fetchData = async () => {
		try {
			setLoading(true);
			// Check if user is logged in
			const isAuthenticated = await checkAuth(apiUrl);
			if (!isAuthenticated) {
				addToast({
					title: "Session expired. Please sign in again.",
					color: "warning"
				});
				router.push("/login?reconnect=true");
				return;
			}

			// Check onboarding and email sync status
			const onboardingResp = await fetch(`${apiUrl}/api/users/onboarding-status`, {
				credentials: "include"
			});
			if (onboardingResp.ok) {
				const data = await onboardingResp.json();
				if (!data.has_completed_onboarding) {
					router.push("/onboarding");
					return;
				}
				if (!data.has_email_sync_configured) {
					router.push("/email-sync-setup");
					return;
				}
			}

			// Fetch applications (if user is logged in)
			const headers: HeadersInit = {};
			if (viewAs) {
				headers["X-View-As"] = viewAs;
			}
			const response = await fetch(`${apiUrl}/get-emails?page=${currentPage}`, {
				method: "GET",
				credentials: "include", // Include cookies for session management
				headers
			});

			if (!response.ok) {
				if (response.status === 403) {
					const onboardingRequired = response.headers.get("X-Onboarding-Required");
					if (onboardingRequired === "true") {
						router.push("/onboarding");
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
			setTotalPages(result.totalPages);

			setData(result);
		} catch {
			setError("Failed to load applications");
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		fetchData();
	}, [apiUrl, router, currentPage, viewAs]);

	// Fetch role and clients if coach
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
				/* ignore */
			}
		};
		init();
	}, [apiUrl]);

	// Filter data based on search term, status, company, and hide options
	const filteredData = useMemo(() => {
		return data.filter((item) => {
			const matchesSearch =
				!searchTerm ||
				item.company_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
				item.job_title.toLowerCase().includes(searchTerm.toLowerCase()) ||
				item.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
				(item.normalized_job_title &&
					item.normalized_job_title.toLowerCase().includes(searchTerm.toLowerCase()));

			const matchesStatus = !statusFilter || item.application_status === statusFilter;
			const matchesCompany = !companyFilter || item.company_name === companyFilter;
			const matchesNormalizedJobTitle =
				!normalizedJobTitleFilter || item.normalized_job_title === normalizedJobTitleFilter;

			const isNotRejection = !hideRejections || !item.application_status.toLowerCase().includes("reject");

			const isNotApplicationConfirmation =
				!hideApplicationConfirmations ||
				!item.application_status.toLowerCase().includes("application confirmation");

			return (
				matchesSearch &&
				matchesStatus &&
				matchesCompany &&
				matchesNormalizedJobTitle &&
				isNotRejection &&
				isNotApplicationConfirmation
			);
		});
	}, [
		data,
		searchTerm,
		statusFilter,
		companyFilter,
		normalizedJobTitleFilter,
		hideRejections,
		hideApplicationConfirmations
	]);

	const nextPage = () => {
		if (currentPage < totalPages) {
			setCurrentPage(currentPage + 1);
		}
	};

	const prevPage = () => {
		if (currentPage > 1) {
			setCurrentPage(currentPage - 1);
		}
	};

	async function downloadCsv() {
		setDownloading(true);
		posthog.capture("csv_export_clicked", { application_count: data.length });
		try {
			const response = await fetch(`${apiUrl}/process-csv`, {
				method: "GET",
				credentials: "include"
			});

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
			// Create a download link to trigger the file download
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
	}

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

	const handleRemoveItem = async (id: string) => {
		try {
			// Make a DELETE request to the backend
			const response = await fetch(`${apiUrl}/delete-email/${id}`, {
				method: "DELETE",
				credentials: "include" // Include cookies for authentication
			});

			if (!response.ok) {
				throw new Error("Failed to delete the item");
			}

			// If the deletion is successful, update the local state
			setData((prevData) => prevData.filter((item) => item.id !== id));

			addToast({
				title: "Item removed successfully",
				color: "success"
			});
		} catch (error) {
			addToast({
				title: "Failed to remove item",
				description: "Please try again or contact support.",
				color: "danger"
			});
		}
	};

	return (
		<>
			<Navbar isPremium={isPremium} onSettingsClick={() => setShowSettingsModal(true)} />
			{/* Processing banner - shows while scanning emails */}
			{processingStatus?.status === "processing" && (
				<ProcessingBanner
					found={processingStatus.applications_found}
					processed={processingStatus.processed_emails}
					total={processingStatus.total_emails}
				/>
			)}

			{/* Contributor badge */}
			{contributionCents > 0 && (
				<div className="mb-4 p-4 rounded bg-blue-50 dark:bg-blue-900/20 flex items-center gap-2">
					<ContributorBadge monthlyCents={contributionCents} onClick={() => setShowSettingsModal(true)} />
					<span className="text-sm text-gray-600 dark:text-gray-300">
						Your contribution helps us help more jobseekers.
					</span>
				</div>
			)}

			{/* Header with tracking info and refresh */}
			<div className="flex items-center justify-between mb-4 px-6 pt-4">
				<p className="text-sm text-gray-500 dark:text-gray-400">
					Tracking since {formatStartDate(startDate)}
					<button
						className="ml-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50"
						disabled={processingStatus?.status === "processing"}
						title="Edit start date"
						onClick={() => {
							posthog.capture("start_date_edit_opened");
							setShowStartDateModal(true);
						}}
					>
						<svg className="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path
								d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"
								strokeLinecap="round"
								strokeLinejoin="round"
								strokeWidth={2}
							/>
						</svg>
					</button>
					<span className="mx-2">•</span>
					Last synced:{" "}
					{processingStatus?.status === "processing"
						? "Scanning now..."
						: formatLastSynced(processingStatus?.last_scan_at || null)}
				</p>
				<button
					className="flex items-center gap-2 px-3 py-1.5 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white disabled:opacity-50 rounded border border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700"
					disabled={refreshing || processingStatus?.status === "processing"}
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
					Refresh
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
			<JobApplicationsDashboard
				companyFilter={companyFilter}
				currentPage={currentPage}
				data={filteredData}
				downloading={downloading}
				hideApplicationConfirmations={hideApplicationConfirmations}
				hideRejections={hideRejections}
				loading={loading}
				normalizedJobTitleFilter={normalizedJobTitleFilter}
				readOnly={!!viewAs}
				searchTerm={searchTerm}
				statusFilter={statusFilter}
				totalPages={totalPages}
				onCompanyFilterChange={setCompanyFilter}
				onDownloadCsv={downloadCsv}
				onHideApplicationConfirmationsChange={setHideApplicationConfirmations}
				onHideRejectionsChange={setHideRejections}
				onNextPage={nextPage}
				onNormalizedJobTitleFilterChange={setNormalizedJobTitleFilter}
				onPrevPage={prevPage}
				onRefreshData={fetchData}
				onRemoveItem={handleRemoveItem}
				onSearchChange={setSearchTerm}
				onStatusFilterChange={setStatusFilter}
			/>

			{/* Settings modal */}
			<SettingsModal
				isOpen={showSettingsModal}
				onClose={() => setShowSettingsModal(false)}
				onSubscriptionChange={() => {
					// Refresh premium status when subscription changes
					fetchPremiumStatus();
				}}
			/>

			{/* Session expired modal */}
			{showSessionExpired && (
				<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
					<div className="bg-white dark:bg-gray-800 rounded-lg max-w-sm w-full mx-4 p-6">
						<h2 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white text-center">
							Reconnect to refresh
						</h2>
						<p className="text-gray-600 dark:text-gray-300 mb-6 text-center">
							Your existing data is still available. Sign in again to scan for new applications.
						</p>
						<div
							onClick={() => {
								posthog.capture("token_expired_reauth");
							}}
						>
							<GoogleEmailSyncButton />
						</div>
						<button
							className="w-full mt-3 py-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 text-sm"
							onClick={() => {
								setShowSessionExpired(false);
							}}
						>
							Cancel
						</button>
					</div>
				</div>
			)}

			{/* Change start date modal */}
			<ChangeStartDateModal
				currentDate={startDate}
				isLoading={updatingStartDate}
				isOpen={showStartDateModal}
				onClose={() => setShowStartDateModal(false)}
				onSave={handleStartDateSave}
			/>
		</>
	);
}
