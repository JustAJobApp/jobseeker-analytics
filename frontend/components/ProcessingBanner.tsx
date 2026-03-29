"use client";

import { Progress } from "@heroui/react";
import { CogIcon, XMarkIcon } from "@heroicons/react/20/solid";

interface ProcessingBannerProps {
	processed: number;
	total: number;
	found: number;
	scanStartDate?: string | null;
	scanEndDate?: string | null;
	onCancel?: () => void;
	cancelling?: boolean;
}

const formatDate = (isoString: string | null | undefined): string => {
	if (!isoString) return "";
	return new Date(isoString).toLocaleDateString("en-US", {
		month: "short",
		day: "numeric",
		year: "numeric"
	});
};

export default function ProcessingBanner({
	processed,
	total,
	found,
	scanStartDate,
	scanEndDate,
	onCancel,
	cancelling
}: ProcessingBannerProps) {
	const percent = total > 0 ? Math.round((processed / total) * 100) : 0;

	const dateRangeText =
		scanStartDate || scanEndDate
			? `${formatDate(scanStartDate) || "Start"}${scanEndDate ? ` - ${formatDate(scanEndDate)}` : " - Present"}`
			: null;

	return (
		<div className="bg-blue-50 dark:bg-blue-900/30 border-b border-blue-200 dark:border-blue-800 px-4 py-3 mb-4 rounded-lg">
			<div className="max-w-4xl mx-auto">
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-3">
						<CogIcon className="w-5 h-5 animate-spin text-blue-600 dark:text-blue-400" />
						<div className="flex flex-col">
							<span className="text-blue-900 dark:text-blue-100">
								Scanning your inbox... {processed}/{total} emails
							</span>
							{dateRangeText && (
								<span className="text-xs text-blue-600 dark:text-blue-400">
									Date range: {dateRangeText}
								</span>
							)}
						</div>
					</div>
					<div className="flex items-center gap-4">
						<span className="text-blue-600 dark:text-blue-400 font-medium">
							{found} job search email{found !== 1 ? "s" : ""} found
						</span>
						{onCancel && (
							<button
								className="flex items-center gap-1 px-2 py-1 text-sm text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/30 rounded disabled:opacity-50"
								disabled={cancelling}
								title="Cancel scan"
								onClick={onCancel}
							>
								<XMarkIcon className="w-4 h-4" />
								{cancelling ? "Cancelling..." : "Cancel"}
							</button>
						)}
					</div>
				</div>
				<Progress
					aria-label="Email processing progress"
					className="mt-2"
					color="primary"
					size="sm"
					value={percent}
				/>
			</div>
		</div>
	);
}
