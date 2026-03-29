"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Button, Card, CardBody } from "@heroui/react";

import { Navbar } from "@/components/navbar";
import Spinner from "@/components/spinner";

function ThankYouContent() {
	const router = useRouter();
	const searchParams = useSearchParams();
	const [isLoading, setIsLoading] = useState(true);
	const [monthlyPrice, setMonthlyPrice] = useState<number | null>(null);
	const [hasCompletedOnboarding, setHasCompletedOnboarding] = useState(false);

	useEffect(() => {
		const fetchStatus = async () => {
			const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

			try {
				// Fetch premium status and onboarding status in parallel
				const [premiumRes, onboardingRes] = await Promise.all([
					fetch(`${apiUrl}/settings/premium-status`, {
						method: "GET",
						credentials: "include"
					}),
					fetch(`${apiUrl}/api/users/onboarding-status`, {
						method: "GET",
						credentials: "include"
					})
				]);

				if (premiumRes.ok) {
					const data = await premiumRes.json();
					setMonthlyPrice(data.subscription_price_cents);
				}

				if (onboardingRes.ok) {
					const data = await onboardingRes.json();
					setHasCompletedOnboarding(data.has_completed_onboarding ?? false);
				}
			} catch (error) {
				console.error("Error fetching status:", error);
			} finally {
				setIsLoading(false);
			}
		};

		// Small delay to ensure Stripe webhook has processed
		setTimeout(fetchStatus, 1000);
	}, [searchParams]);

	const handleContinue = () => {
		router.push(hasCompletedOnboarding ? "/dashboard" : "/onboarding");
	};

	if (isLoading) {
		return (
			<div className="flex flex-col min-h-screen">
				<Navbar />
				<main className="flex-grow flex items-center justify-center bg-gray-50 dark:bg-gray-900">
					<Spinner />
				</main>
			</div>
		);
	}

	return (
		<div className="flex flex-col min-h-screen">
			<Navbar />
			<main className="flex-grow flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
				<Card className="max-w-md w-full">
					<CardBody className="text-center py-8 px-6">
						<div className="text-5xl mb-4">💙</div>
						<h1 className="text-2xl font-bold mb-2">Thank you for supporting JustAJobApp!</h1>
						{monthlyPrice && (
							<p className="text-gray-600 dark:text-gray-300 mb-4">
								Your ${monthlyPrice / 100}/month subscription is now active.
							</p>
						)}
						<p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
							You can manage or cancel anytime from{" "}
							<a className="underline" href="/settings">
								Settings.
							</a>
						</p>
						<Button color="primary" size="lg" onPress={handleContinue}>
							{hasCompletedOnboarding ? "Back to Dashboard" : "Continue Setup →"}
						</Button>
					</CardBody>
				</Card>
			</main>
		</div>
	);
}

export default function ThankYouPage() {
	return (
		<Suspense
			fallback={
				<div className="flex flex-col min-h-screen">
					<Navbar />
					<main className="flex-grow flex items-center justify-center">
						<Spinner />
					</main>
				</div>
			}
		>
			<ThankYouContent />
		</Suspense>
	);
}
