"use client";
import { useState, useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import { addToast } from "@heroui/toast";
import React from "react";
import posthog from "posthog-js";

import JobApplicationsDashboard, { Application } from "@/components/JobApplicationsDashboard";
import ResponseRateCard from "@/components/response_rate_card";
import UniqueOpenRateChart from "@/components/response_rate_chart";
import { checkAuth } from "@/utils/auth";

export default function Dashboard() {
	const router = useRouter();
	const [data, setData] = useState<Application[]>([]);
	const [loading, setLoading] = useState(true);
	const [downloading, setDownloading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [currentPage, setCurrentPage] = useState(1);
	const [totalPages, setTotalPages] = useState(1);
	const [searchTerm, setSearchTerm] = useState("");
	const [statusFilter, setStatusFilter] = useState("");
	const [companyFilter, setCompanyFilter] = useState("");
	const [hideRejections, setHideRejections] = useState<boolean>(true);
	const [hideApplicationConfirmations, setHideApplicationConfirmations] = useState<boolean>(true);
	const [normalizedJobTitleFilter, setNormalizedJobTitleFilter] = useState("");

	const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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
						posthog.identify(userData.user_id);
					}
				}
			} catch (error) {
				// Silently fail PostHog identification - don't block the dashboard
			}
		};
		identifyUser();
	}, [apiUrl]);

	const fetchData = async () => {
		try {
			setLoading(true);
			// Check if user is logged in
			const isAuthenticated = await checkAuth(apiUrl);
			if (!isAuthenticated) {
				addToast({
					title: "You need to be logged in to access this page.",
					color: "warning"
				});
				router.push("/");
				return;
			}

			// Fetch applications (if user is logged in)
			const response = await fetch(`${apiUrl}/get-emails?page=${currentPage}`, {
				method: "GET",
				credentials: "include" // Include cookies for session management
			});

			if (!response.ok) {
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
	}, [apiUrl, router, currentPage]);

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

	const responseRateContent = (
		<>
			<div className="flex flex-col gap-4 mt-4 mb-6 md:flex-row">
				<div className="w-full md:w-[30%]">
					<ResponseRateCard />
				</div>
				<div className="md:w-[70%]">
					<UniqueOpenRateChart />
				</div>
			</div>
		</>
	);

	return (
		<JobApplicationsDashboard
			companyFilter={companyFilter}
			currentPage={currentPage}
			data={filteredData}
			downloading={downloading}
			hideApplicationConfirmations={hideApplicationConfirmations}
			hideRejections={hideRejections}
			loading={loading}
			normalizedJobTitleFilter={normalizedJobTitleFilter}
			responseRate={responseRateContent}
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
	);
}
