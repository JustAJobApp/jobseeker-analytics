"use client";

import React, { useState, useEffect } from "react";
import { Table, TableHeader, TableBody, TableColumn, TableRow, TableCell } from "@heroui/table";
import { DatePicker } from "@heroui/react";
import { CalendarDate } from "@internationalized/date";
import { useRouter } from "next/navigation";
import {
	Button,
	Dropdown,
	DropdownItem,
	DropdownMenu,
	DropdownSection,
	DropdownTrigger,
	Modal,
	ModalBody,
	ModalContent,
	ModalFooter,
	ModalHeader,
	Tooltip
} from "@heroui/react";

import JobApplicationModal from "./JobApplicationModal";

import { DownloadIcon, SortIcon, TrashIcon, EditIcon, PlusIcon } from "@/components/icons";

export interface Application {
	id?: string;
	company_name: string;
	application_status: string;
	received_at: string;
	job_title: string;
	normalized_job_title?: string;
	subject: string;
	email_from: string;
}

interface JobApplicationsDashboardProps {
	title?: string;
	data: Application[];
	loading: boolean;
	downloading: boolean;
	onDownloadCsv: () => void;
	onRemoveItem: (id: string) => void;
	initialSortKey?: string;
	responseRate?: React.ReactNode;
	searchTerm?: string;
	onSearchChange?: (term: string) => void;
	statusFilter?: string;
	onStatusFilterChange?: (status: string) => void;
	companyFilter?: string;
	onCompanyFilterChange?: (company: string) => void;
	normalizedJobTitleFilter?: string;
	onNormalizedJobTitleFilterChange?: (title: string) => void;
	hideRejections?: boolean;
	onHideRejectionsChange?: (hide: boolean) => void;
	hideApplicationConfirmations?: boolean;
	onHideApplicationConfirmationsChange?: (hide: boolean) => void;
	onNextPage: () => void;
	onPrevPage: () => void;
	currentPage: number;
	totalPages: number;
	onRefreshData?: () => void;
}

// Load sort key from localStorage or use default
const getInitialSortKey = (key: string) => {
	return typeof window !== "undefined" ? localStorage.getItem("sortKey") || key : key;
};

//Function to get the CSS class based on application status
function getStatusClass(status: string) {
	const normalized = status?.toLowerCase();
	switch (normalized) {
		case "rejection":
			return "bg-red-100 text-red-800 dark:bg-red-600 dark:text-white";
		case "offer made":
			return "bg-green-100 text-green-800 dark:bg-success dark:text-white";
		case "application confirmation":
			return "bg-blue-100 text-blue-800 dark:bg-primary dark:text-white";
		case "availability request":
			return "bg-emerald-100 text-emerald-800 dark:bg-emerald-600 dark:text-white";
		case "information request":
			return "bg-teal-100 text-teal-800 dark:bg-teal-600 dark:text-white";
		case "assessment sent":
			return "bg-yellow-100 text-yellow-800 dark:bg-yellow-600 dark:text-white";
		case "interview invitation":
			return "bg-cyan-100 text-cyan-800 dark:bg-cyan-600 dark:text-white";
		case "did not apply - inbound request":
			return "bg-purple-100 text-purple-800 dark:bg-purple-600 dark:text-white";
		case "action required from company":
			return "bg-lime-100 text-lime-800 dark:bg-lime-600 dark:text-white";
		case "hiring freeze notification":
			return "bg-orange-100 text-orange-800 dark:bg-orange-600 dark:text-white";
		case "withdrew application":
			return "bg-fuchsia-100 text-fuchsia-800 dark:bg-fuchsia-600 dark:text-white";
		case "false positive":
			return "bg-amber-100 text-amber-800 dark:bg-amber-600 dark:text-white";
		default:
			return "bg-zinc-200 text-zinc-800 dark:bg-zinc-600 dark:text-white";
	}
}

export default function JobApplicationsDashboard({
	title = "Job Applications Dashboard",
	data,
	loading,
	downloading,
	onDownloadCsv,
	onRemoveItem,
	initialSortKey = "Date (Newest)",
	responseRate,
	searchTerm = "",
	onSearchChange,
	statusFilter = "",
	onStatusFilterChange,
	companyFilter = "",
	onCompanyFilterChange,
	normalizedJobTitleFilter = "",
	onNormalizedJobTitleFilterChange,
	hideRejections = true,
	onHideRejectionsChange,
	hideApplicationConfirmations = true,
	onHideApplicationConfirmationsChange,
	onRefreshData,
	...props
}: JobApplicationsDashboardProps) {
	const [sortedData, setSortedData] = useState<Application[]>([]);
	const [selectedKeys, setSelectedKeys] = useState(new Set([getInitialSortKey(initialSortKey)]));
	const [showModal, setShowModal] = useState(false);
	const [selectedDate, setSelectedDate] = useState<CalendarDate | null>(null);
	const [isSaving, setIsSaving] = useState(false);
	const [isNewUser, setIsNewUser] = useState(false);
	const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
	const router = useRouter();
	const [showDelete, setShowDelete] = useState(false);
	const [itemToRemove, setItemToRemove] = useState<string | null>(null);

	const [currentPage, setCurrentPage] = useState(1);
	const pageSize = 10;

	// Add/Edit modal state
	const [showApplicationModal, setShowApplicationModal] = useState(false);
	const [modalMode, setModalMode] = useState<"create" | "edit">("create");
	const [selectedApplication, setSelectedApplication] = useState<Application | null>(null);

	// Get unique statuses and companies for filter dropdowns
	const uniqueStatuses = React.useMemo(() => {
		const statuses = new Set(data.map((item) => item.application_status).filter(Boolean));
		return Array.from(statuses).sort();
	}, [data]);

	const uniqueCompanies = React.useMemo(() => {
		const companies = new Set(data.map((item) => item.company_name).filter(Boolean));
		return Array.from(companies).sort();
	}, [data]);

	const uniqueNormalizedJobTitles = React.useMemo(() => {
		const titles = new Set(
			data.map((item) => item.normalized_job_title).filter((title) => title && title.trim() !== "")
		);
		return Array.from(titles).sort();
	}, [data]);

	const selectedValue = React.useMemo(() => Array.from(selectedKeys).join(", ").replace(/_/g, ""), [selectedKeys]);

	const handleSave = async () => {
		if (!selectedDate) return alert("Please select a start date");

		setIsSaving(true);
		const formattedDate = `${selectedDate.year}-${String(selectedDate.month).padStart(2, "0")}-${String(selectedDate.day).padStart(2, "0")}`;
		// Step 1: Save the start date
		const response = await fetch(`${apiUrl}/set-start-date`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ start_date: formattedDate.toString() }),
			credentials: "include"
		});

		if (!response.ok) throw new Error("Failed to save start date");

		// Step 2: Start background task (fetch emails)
		startFetchEmailsBackgroundTask();

		// Step 3: Navigate to processing page
		setIsNewUser(false); // Hide the modal after saving
		setShowModal(false);
		router.push("/processing"); // Navigate to the processing page
	};

	const startFetchEmailsBackgroundTask = async () => {
		// Example background task: Start fetching emails
		const response = await fetch(`${apiUrl}/fetch-emails`, {
			method: "POST", // or GET, depending on your API
			credentials: "include"
		});

		if (!response.ok) {
			return;
		}
	};

	useEffect(() => {
		setShowModal(isNewUser);
	}, [isNewUser]);

	useEffect(() => {
		async function fetchSessionData() {
			const response = await fetch(`${apiUrl}/api/session-data`, {
				method: "GET",
				credentials: "include"
			});
			if (!response.ok) {
				throw new Error(`HTTP error! status: ${response.status}`);
			}
			const data = await response.json();
			setIsNewUser(!!data.is_new_user); // Set the new user flag
			setShowModal(!!data.is_new_user); // Show modal if new user
		}
		fetchSessionData();
	}, []);

	// Sort data based on selected key
	useEffect(() => {
		const sortData = () => {
			const sorted = [...data];
			const sortKey = Array.from(selectedKeys)[0];

			switch (sortKey) {
				case "Date (Newest)":
					sorted.sort((a, b) => new Date(b.received_at).getTime() - new Date(a.received_at).getTime());
					break;
				case "Date (Oldest)":
					sorted.sort((a, b) => new Date(a.received_at).getTime() - new Date(b.received_at).getTime());
					break;
				case "Company":
					sorted.sort((a, b) => a.company_name.localeCompare(b.company_name));
					break;
				case "Job Title":
					sorted.sort((a, b) => a.job_title.localeCompare(b.job_title));
					break;
				case "Normalized Job Title":
					sorted.sort((a, b) => {
						const titleA = a.normalized_job_title?.toLowerCase() || "";
						const titleB = b.normalized_job_title?.toLowerCase() || "";
						return titleA.localeCompare(titleB);
					});
					break;
				case "Status":
					sorted.sort((a, b) => a.application_status.localeCompare(b.application_status));
					break;
				default:
					break;
			}
			setSortedData(sorted);
		};

		if (data.length > 0) {
			sortData();
		} else {
			setSortedData([]);
		}
	}, [selectedKeys, data]);

	const paginatedData = sortedData.slice((currentPage - 1) * pageSize, currentPage * pageSize);

	// Handle sorting selection change and store it in localStorage
	const handleSortChange = (keys: Set<string>) => {
		const sortKey = Array.from(keys)[0];
		localStorage.setItem("sortKey", sortKey);
		setSelectedKeys(new Set([sortKey]));
	};

	// Pagination controls
	const handleNextPage = () => {
		if (currentPage < Math.ceil(sortedData.length / pageSize)) {
			setCurrentPage(currentPage + 1);
		}
	};

	const handlePreviousPage = () => {
		if (currentPage > 1) {
			setCurrentPage(currentPage - 1);
		}
	};

	const handlePageChange = (page: number) => {
		setCurrentPage(page);
	};

	const totalPages = Math.ceil(sortedData.length / pageSize);

	// Add/Edit application handlers
	const handleAddApplication = () => {
		setModalMode("create");
		setSelectedApplication(null);
		setShowApplicationModal(true);
	};

	const handleEditApplication = (application: Application) => {
		setModalMode("edit");
		setSelectedApplication(application);
		setShowApplicationModal(true);
	};

	const handleSaveApplication = async (application: Application) => {
		try {
			const url =
				modalMode === "create" ? `${apiUrl}/job-applications` : `${apiUrl}/job-applications/${application.id}`;

			const method = modalMode === "create" ? "POST" : "PUT";

			const response = await fetch(url, {
				method,
				headers: {
					"Content-Type": "application/json"
				},
				credentials: "include",
				body: JSON.stringify(application)
			});

			if (!response.ok) {
				throw new Error(`Failed to ${modalMode} application`);
			}

			// Refresh the data by calling the parent's refresh function or refetch
			setShowApplicationModal(false);

			// Call the refresh callback if provided
			if (onRefreshData) {
				onRefreshData();
			}
		} catch (error) {
			console.error(`Error ${modalMode === "create" ? "creating" : "updating"} application:`, error);
			throw error;
		}
	};

	return (
		<div className="p-6">
			{/* Modal for New User */}
			<Modal isOpen={showModal} onOpenChange={setShowModal}>
				<ModalContent>
					<ModalHeader>Select Your Job Search Start Date</ModalHeader>
					<ModalBody>
						<DatePicker value={selectedDate} onChange={setSelectedDate} />
					</ModalBody>
					<ModalFooter>
						<Button color="primary" isLoading={isSaving} onPress={handleSave}>
							Save and Continue
						</Button>
					</ModalFooter>
				</ModalContent>
			</Modal>
			<Modal isOpen={showDelete} onOpenChange={(isOpen) => setShowDelete(isOpen)}>
				<ModalContent>
					{(onClose) => (
						<>
							<ModalHeader className="flex flex-col gap-1">Confirm Removal</ModalHeader>
							<ModalBody>
								<p>
									Are you sure you want to remove this row? Every job application impacts your
									metrics, so it's important to keep all records unless we accidentally made a mistake
									and picked up a non-job-related record.
								</p>
							</ModalBody>
							<ModalFooter>
								<Button color="default" variant="ghost" onPress={onClose}>
									Cancel
								</Button>
								<Button
									color="danger"
									onPress={() => {
										if (itemToRemove) {
											onRemoveItem(itemToRemove); // Notify the parent to remove the item
											setItemToRemove(null); // Clear the selected item
											setShowDelete(false); // Close the modal
										}
									}}
								>
									Yes, remove it
								</Button>
							</ModalFooter>
						</>
					)}
				</ModalContent>
			</Modal>
			<h1 className="text-2xl font-bold mt-0">{title}</h1>
			{responseRate}
			<div className="flex flex-wrap items-center justify-between gap-4 mb-4">
				{/* Search and Filter Controls */}
				<div className="flex flex-wrap items-center gap-4 flex-1">
					{/* Search Input */}
					<div className="flex-1 max-w-md">
						<input
							className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white"
							placeholder="Company"
							type="text"
							value={searchTerm}
							onChange={(e) => onSearchChange?.(e.target.value)}
						/>
					</div>

					{/* Status Filter */}
					<Dropdown>
						<DropdownTrigger>
							<Button
								className="pl-3"
								color={statusFilter ? "success" : "primary"}
								isDisabled={!data || data.length === 0}
								startContent={
									<svg
										fill="none"
										height="16"
										stroke="currentColor"
										strokeWidth="2"
										viewBox="0 0 24 24"
										width="16"
									>
										<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
									</svg>
								}
								variant="bordered"
							>
								{statusFilter || "All Statuses"}
								{statusFilter && (
									<span className="ml-2 inline-flex items-center justify-center w-5 h-5 text-xs font-medium bg-success text-white rounded-full">
										+
									</span>
								)}
							</Button>
						</DropdownTrigger>
						<DropdownMenu
							disallowEmptySelection
							aria-label="Status filter"
							selectedKeys={statusFilter ? new Set([statusFilter]) : new Set()}
							selectionMode="single"
							variant="flat"
							onSelectionChange={(keys) => {
								const selectedStatus = Array.from(keys)[0] as string;
								onStatusFilterChange?.(selectedStatus || "");
							}}
						>
							<>
								<DropdownItem key="">All Statuses</DropdownItem>
								{uniqueStatuses.map((status: string) => (
									<DropdownItem key={status}>{status}</DropdownItem>
								))}
							</>
						</DropdownMenu>
					</Dropdown>

					{/* Company Filter */}
					<Dropdown>
						<DropdownTrigger>
							<Button
								className="pl-3"
								color={companyFilter ? "success" : "primary"}
								isDisabled={!data || data.length === 0}
								startContent={
									<svg
										fill="none"
										height="16"
										stroke="currentColor"
										strokeWidth="2"
										viewBox="0 0 24 24"
										width="16"
									>
										<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
									</svg>
								}
								variant="bordered"
							>
								{companyFilter || "All Companies"}
								{companyFilter && (
									<span className="ml-2 inline-flex items-center justify-center w-5 h-5 text-xs font-medium bg-success text-white rounded-full">
										+
									</span>
								)}
							</Button>
						</DropdownTrigger>
						<DropdownMenu
							disallowEmptySelection
							aria-label="Company filter"
							selectedKeys={companyFilter ? new Set([companyFilter]) : new Set()}
							selectionMode="single"
							variant="flat"
							onSelectionChange={(keys) => {
								const selectedCompany = Array.from(keys)[0] as string;
								onCompanyFilterChange?.(selectedCompany || "");
							}}
						>
							<>
								<DropdownItem key="">All Companies</DropdownItem>
								{uniqueCompanies.map((company: string) => (
									<DropdownItem key={company}>{company}</DropdownItem>
								))}
							</>
						</DropdownMenu>
					</Dropdown>

					{/* Normalized Job Title Filter */}
					<Dropdown>
						<DropdownTrigger>
							<Button
								className="pl-3"
								color={normalizedJobTitleFilter ? "success" : "primary"}
								isDisabled={!data || data.length === 0}
								startContent={
									<svg
										fill="none"
										height="16"
										stroke="currentColor"
										strokeWidth="2"
										viewBox="0 0 24 24"
										width="16"
									>
										<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
										<polyline points="3.27 6.96 12 12.01 20.73 6.96" />
										<line x1="12" x2="12" y1="22.08" y2="12" />
									</svg>
								}
								variant="bordered"
							>
								{normalizedJobTitleFilter || "All Job Titles"}
								{normalizedJobTitleFilter && (
									<span className="ml-2 inline-flex items-center justify-center w-5 h-5 text-xs font-medium bg-success text-white rounded-full">
										+
									</span>
								)}
							</Button>
						</DropdownTrigger>
						<DropdownMenu
							disallowEmptySelection
							aria-label="Normalized job title filter"
							selectedKeys={normalizedJobTitleFilter ? new Set([normalizedJobTitleFilter]) : new Set()}
							selectionMode="single"
							variant="flat"
							onSelectionChange={(keys) => {
								const selectedTitle = Array.from(keys)[0] as string;
								onNormalizedJobTitleFilterChange?.(selectedTitle || "");
							}}
						>
							<>
								<DropdownItem key="">All Job Titles</DropdownItem>
								{uniqueNormalizedJobTitles.map((title: string | undefined) =>
									title ? <DropdownItem key={title}>{title}</DropdownItem> : null
								)}
							</>
						</DropdownMenu>
					</Dropdown>

					{/* Hide Rejections Checkbox */}
					<div className="flex items-center gap-2">
						<input
							checked={hideRejections}
							className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600"
							id="hide-rejections"
							type="checkbox"
							onChange={(e) => onHideRejectionsChange?.(e.target.checked)}
						/>
						<label
							className="text-sm font-medium text-gray-700 dark:text-gray-300"
							htmlFor="hide-rejections"
						>
							Hide Rejections
						</label>
					</div>

					{/* Hide Application Confirmations Checkbox */}
					<div className="flex items-center gap-2">
						<input
							checked={hideApplicationConfirmations}
							className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600"
							id="hide-application-confirmations"
							type="checkbox"
							onChange={(e) => onHideApplicationConfirmationsChange?.(e.target.checked)}
						/>
						<label
							className="text-sm font-medium text-gray-700 dark:text-gray-300"
							htmlFor="hide-application-confirmations"
						>
							Hide Application Confirmations
						</label>
					</div>
				</div>

				{/* Sort and Download Controls */}
				<div className="flex items-center gap-4">
					<Dropdown>
						<DropdownTrigger>
							<Button
								className="pl-3"
								color="primary"
								data-testid="Sort By"
								isDisabled={!data || data.length === 0}
								startContent={<SortIcon />}
								variant="bordered"
							>
								{selectedValue}
							</Button>
						</DropdownTrigger>
						<DropdownMenu
							disallowEmptySelection
							aria-label="Single selection example"
							selectedKeys={selectedKeys}
							selectionMode="single"
							variant="flat"
							onSelectionChange={(keys) => handleSortChange(keys as Set<string>)}
						>
							<DropdownSection title="Sort By">
								<DropdownItem key="Date (Newest)">Date Received (Newest First)</DropdownItem>
								<DropdownItem key="Date (Oldest)">Date Received (Oldest First)</DropdownItem>
								<DropdownItem key="Company">Company (A-Z)</DropdownItem>
								<DropdownItem key="Normalized Job Title">Normalized Job Title (A-Z)</DropdownItem>
								<DropdownItem key="Job Title">Job Title (A-Z)</DropdownItem>
								<DropdownItem key="Status">Application Status</DropdownItem>
							</DropdownSection>
						</DropdownMenu>
					</Dropdown>

					<Button
						className="w-full sm:w-auto text-white"
						color="success"
						isDisabled={!data || data.length === 0}
						isLoading={downloading}
						startContent={<DownloadIcon />}
						onPress={onDownloadCsv}
					>
						Download CSV
					</Button>

					<Button
						className="w-full sm:w-auto"
						color="primary"
						startContent={<PlusIcon />}
						onPress={handleAddApplication}
					>
						Add Application
					</Button>
				</div>
			</div>

			{loading ? (
				<p>Loading applications...</p>
			) : (
				<div className="overflow-x-auto bg-white dark:bg-black shadow-md rounded-lg">
					<Table aria-label="Applications Table">
						<TableHeader>
							<TableColumn className="text-center">Company</TableColumn>
							<TableColumn className="text-center">Status</TableColumn>
							<TableColumn className="text-center">Received</TableColumn>
							<TableColumn className="text-center">Job Title</TableColumn>
							<TableColumn className="text-center">Normalized Job Title</TableColumn>
							<TableColumn className="text-center">Subject</TableColumn>
							<TableColumn className="text-center">Sender</TableColumn>
							<TableColumn className="text-center">Actions</TableColumn>
						</TableHeader>
						<TableBody>
							{paginatedData.map((item) => (
								<TableRow
									key={item.id || item.received_at}
									className="hover:bg-default-100 transition-colors"
								>
									<TableCell className="max-w-[100px] text-center">
										{item.company_name || "--"}
									</TableCell>
									<TableCell className="max-w-[120px] break-words whitespace-normal text-center">
										<span
											className={`inline-flex items-center justify-center px-1.5 py-1 rounded text-sm font-medium ${getStatusClass(item.application_status)}`}
										>
											{item.application_status || "--"}
										</span>
									</TableCell>
									<TableCell className="text-center">
										{new Date(item.received_at).toLocaleDateString() || "--"}
									</TableCell>
									<TableCell className="max-w-[136px] break-words whitespace-normal text-center">
										{item.job_title || "--"}
									</TableCell>
									<TableCell className="max-w-[136px] break-words whitespace-normal text-center">
										{item.normalized_job_title || "--"}
									</TableCell>
									<TableCell className="max-w-[200px] break-words text-center">
										{item.subject || "--"}
									</TableCell>
									<TableCell className="max-w-[220px] break-words whitespace-normal text-center">
										{item.email_from || "--"}
									</TableCell>
									<TableCell className="text-center">
										<div className="flex justify-center gap-2">
											<Tooltip content="Edit">
												<Button
													isIconOnly
													size="sm"
													variant="light"
													onPress={() => {
														setSelectedApplication(item);
														setModalMode("edit");
														setShowApplicationModal(true);
													}}
												>
													<EditIcon className="text-gray-800 dark:text-gray-300" />
												</Button>
											</Tooltip>
											<Tooltip content="Remove">
												<Button
													isIconOnly
													size="sm"
													variant="light"
													onPress={() => {
														setItemToRemove(item.id || null);
														setShowDelete(true);
													}}
												>
													<TrashIcon className="text-gray-800 dark:text-gray-300" />
												</Button>
											</Tooltip>
										</div>
									</TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
				</div>
			)}
			<div className="flex justify-between items-center mt-4">
				<Button disabled={currentPage === 1} onPress={handlePreviousPage}>
					Previous
				</Button>
				<span>{`${currentPage} of ${totalPages}`}</span>
				<Button disabled={currentPage === totalPages} onPress={handleNextPage}>
					Next
				</Button>
			</div>

			{/* Add/Edit Application Modal */}
			<JobApplicationModal
				application={selectedApplication}
				isOpen={showApplicationModal}
				mode={modalMode}
				onOpenChange={setShowApplicationModal}
				onSave={handleSaveApplication}
			/>
		</div>
	);
}
