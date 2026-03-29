"use client";

import { useState, useMemo } from "react";
import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, Button } from "@heroui/react";

interface ChangeStartDateModalProps {
	isOpen: boolean;
	currentDate: string | null;
	isLoading: boolean;
	isPremium?: boolean;
	onClose: () => void;
	onSave: (data: { preset: string; custom_date?: string; fetch_order: string; end_date: string | null }) => void;
	onUpgrade?: () => void;
}

function formatDate(date: Date): string {
	return date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export default function ChangeStartDateModal({
	isOpen,
	currentDate,
	isLoading,
	isPremium,
	onClose,
	onSave,
	onUpgrade
}: ChangeStartDateModalProps) {
	const [customDate, setCustomDate] = useState(currentDate ? currentDate.split("T")[0] : "");

	// Parse the current date for comparison
	const currentStartDate = useMemo(() => {
		if (!currentDate) return null;
		return new Date(currentDate);
	}, [currentDate]);

	// Calculate what the display range will be
	const selectedDate = useMemo(() => {
		if (!customDate) return null;
		return new Date(customDate + "T00:00:00");
	}, [customDate]);

	// Check if the new date is earlier than current (will trigger backfill)
	const willBackfill = useMemo(() => {
		if (!selectedDate || !currentStartDate) return false;
		return selectedDate < currentStartDate;
	}, [selectedDate, currentStartDate]);

	const handleSave = () => {
		if (customDate) {
			onSave({ preset: "custom", custom_date: customDate, fetch_order: "recent_first", end_date: null });
		}
	};

	const isValid = customDate;

	// Free user upgrade prompt
	if (!isPremium) {
		return (
			<Modal data-testid="start-date-modal" isOpen={isOpen} onClose={onClose}>
				<ModalContent>
					<ModalHeader>Unlock your full history</ModalHeader>
					<ModalBody>
						<p className="text-default-600 mb-4">
							Upgrade to choose your scan start date and access your full email history.
						</p>
						<Button className="w-full" color="primary" size="lg" onPress={onUpgrade}>
							Upgrade — $5/mo
						</Button>
					</ModalBody>
					<ModalFooter>
						<Button color="default" variant="light" onPress={onClose}>
							Close
						</Button>
					</ModalFooter>
				</ModalContent>
			</Modal>
		);
	}

	// Premium user date picker
	return (
		<Modal data-testid="start-date-modal" isOpen={isOpen} onClose={onClose}>
			<ModalContent>
				<ModalHeader>Change scan start date</ModalHeader>
				<ModalBody>
					<div className="space-y-4">
						<div>
							<label className="block text-sm font-medium text-default-700 mb-2">Scan emails from:</label>
							<input
								className="w-full px-3 py-2 border border-divider rounded-lg focus:outline-none focus:ring-2 focus:ring-primary bg-content1 text-foreground"
								max={new Date().toISOString().split("T")[0]}
								type="date"
								value={customDate}
								onChange={(e) => setCustomDate(e.target.value)}
							/>
						</div>

						{selectedDate && (
							<p className="text-sm text-default-500">
								Currently showing:{" "}
								<span className="text-foreground font-medium">{formatDate(selectedDate)} → today</span>
							</p>
						)}

						{willBackfill && (
							<p className="text-sm text-warning">
								Changing this date will scan your inbox for older emails.
							</p>
						)}
					</div>
				</ModalBody>
				<ModalFooter>
					<Button color="default" disabled={isLoading} variant="light" onPress={onClose}>
						Close
					</Button>
					<Button color="primary" disabled={!isValid || isLoading} isLoading={isLoading} onPress={handleSave}>
						Save
					</Button>
				</ModalFooter>
			</ModalContent>
		</Modal>
	);
}
