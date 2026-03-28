"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardBody, CardHeader } from "@heroui/react";

import { Navbar } from "@/components/navbar";
import GoogleSignupButton from "@/components/GoogleSignupButton";
import { checkAuth } from "@/utils/auth";
import Spinner from "@/components/spinner";

const TIER_INFO: Record<string, { name: string; price: string; description: string }> = {
	subsidized: {
		name: "Subsidized",
		price: "$0/month",
		description: "Fully covered by the community"
	},
	standard: {
		name: "Standard",
		price: "$12/month",
		description: "Cover your costs + help 1 other person"
	},
	sustainer: {
		name: "Sustainer",
		price: "$25/month",
		description: "Cover your costs + help 3 other people"
	},
	custom: {
		name: "Custom",
		price: "Custom amount",
		description: "Pay what feels right"
	}
};

function SignupContent() {
	const [isCheckingAuth, setIsCheckingAuth] = useState(true);
	const [marketingConsent, setMarketingConsent] = useState(false);
	const router = useRouter();
	const searchParams = useSearchParams();
	const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

	// Get tier params from URL (passed from pricing page)
	const tier = searchParams.get("tier");
	const amount = searchParams.get("amount");
	const tierInfo = tier ? TIER_INFO[tier] : null;

	useEffect(() => {
		// Store tier selection in localStorage for after OAuth redirect
		if (tier) {
			localStorage.setItem("pendingTier", tier);
			if (amount) {
				localStorage.setItem("pendingAmount", amount);
			}
		}

		// Check for existing session
		checkAuth(apiUrl).then((authenticated) => {
			if (authenticated) {
				// Already logged in - check onboarding status and redirect
				fetch(`${apiUrl}/api/users/onboarding-status`, {
					credentials: "include"
				})
					.then((res) => res.json())
					.then((data) => {
						if (data.has_completed_onboarding) {
							if (data.has_email_sync_configured) {
								router.push("/dashboard");
							} else {
								router.push("/email-sync-setup");
							}
						} else {
							// Pass tier as URL param to ensure it's not lost
							const params = new URLSearchParams();
							if (tier) params.set("tier", tier);
							if (amount) params.set("amount", amount);
							router.push(`/onboarding?${params.toString()}`);
						}
					})
					.catch(() => {
						setIsCheckingAuth(false);
					});
			} else {
				setIsCheckingAuth(false);
			}
		});
	}, [apiUrl, router, tier, amount]);

	if (isCheckingAuth) {
		return (
			<div className="flex flex-col min-h-screen">
				<Navbar />
				<main className="flex-grow flex items-center justify-center">
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
					<CardHeader className="flex flex-col gap-1 items-center py-8">
						<h1 className="text-2xl font-bold">Create Your Account</h1>
						{tierInfo && (
							<div className="mt-4 p-4 bg-emerald-50 dark:bg-emerald-900/30 rounded-lg w-full text-center">
								<p className="text-sm text-gray-600 dark:text-gray-300">Selected plan:</p>
								<p className="font-semibold text-emerald-700 dark:text-emerald-300">
									{tierInfo.name} - {tierInfo.price}
								</p>
								<p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{tierInfo.description}</p>
							</div>
						)}
					</CardHeader>
					<CardBody className="pb-8 space-y-6">
						<div className="space-y-4">
							<p className="text-sm text-gray-600 dark:text-gray-300 text-center">
								Sign up with your Google account to get started. We only need your email address to
								create your account.
							</p>
							<label className="flex items-start gap-2 cursor-pointer">
								<input
									type="checkbox"
									checked={marketingConsent}
									onChange={(e) => setMarketingConsent(e.target.checked)}
									className="mt-0.5 h-4 w-4 rounded border-gray-300 accent-emerald-600"
								/>
								<span className="text-xs text-gray-500 dark:text-gray-400">
									I&apos;d like to receive email updates about my account, tips, and occasional offers. You can unsubscribe at any time.
								</span>
							</label>
							<GoogleSignupButton marketingConsent={marketingConsent} />
						</div>

						<div className="border-t border-gray-200 dark:border-gray-700 pt-4">
							<p className="text-xs text-gray-500 text-center">
								Already have an account?{" "}
								<a className="text-emerald-600 hover:underline" href="/login">
									Login here
								</a>
							</p>
						</div>
					</CardBody>
				</Card>
			</main>
		</div>
	);
}

export default function SignupPage() {
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
			<SignupContent />
		</Suspense>
	);
}
