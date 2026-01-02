// frontend/app/login/page.tsx

"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Input, Button, Card, CardBody, CardHeader } from "@heroui/react";

import { Navbar } from "@/components/navbar";
import GoogleLoginButton from "@/components/GoogleLoginButton";
import { checkAuth } from "@/utils/auth";

export default function LoginPage() {
	const [email, setEmail] = useState("");
	const [isVerified, setIsVerified] = useState(false);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState("");
	const router = useRouter();
	const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

	useEffect(() => {
		// On load, check for existing session
		checkAuth(apiUrl).then((authenticated) => {
			if (authenticated) {
				router.push("/dashboard");
			}
		});
	}, [apiUrl, router]);

	const handleVerifyEmail = async (e: React.FormEvent) => {
		e.preventDefault();
		setLoading(true);
		setError("");

		try {
			const response = await fetch(`${apiUrl}/verify-beta-email`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email })
			});
			const data = await response.json();
			if (data.is_active == "True") {
				setIsVerified(true);
			} else {
				setIsVerified(false);
			}
		} catch (err) {
			setError("Verification failed. Please try again.");
		} finally {
			setLoading(false);
		}
	};

	const handleGoogleLogin = () => {
		window.location.href = `${apiUrl}/auth/google`; // Initiate OAuth
	};

	return (
		<div className="flex flex-col min-h-screen">
			<Navbar />
			<main className="flex-grow flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
				<Card className="max-w-md w-full">
					<CardHeader className="flex flex-col gap-1 items-center py-8">
						<h1 className="text-2xl font-bold">Welcome back!</h1>
						{!isVerified && (
							<p className="text-sm text-gray-500">
								If you need help, email{" "}
								<a
									href="mailto:help@justajobapp.com?subject=Beta%20Login%20Page%20Help"
									target="_blank"
								>
									help@justajobapp.com
								</a>
							</p>
						)}
					</CardHeader>
					<CardBody className="pb-8">
						{!isVerified ? (
							<form className="space-y-4" onSubmit={handleVerifyEmail}>
								<Input
									required
									label="Email Address"
									placeholder="Enter the email approved for beta access."
									type="email"
									value={email}
									onChange={(e) => setEmail(e.target.value)}
								/>
								<Button className="w-full bg-emerald-600 text-white" isLoading={loading} type="submit">
									Continue
								</Button>
								<span className="block text-sm text-gray-500 text-center">
									Not in the official beta? Join the waitlist{" "}
									<a
										className="text-emerald-600 hover:underline text-sm"
										href="https://its.justajobapp.com/"
										target="_blank"
									>
										here.
									</a>
								</span>
							</form>
						) : (
							<GoogleLoginButton />
						)}
					</CardBody>
				</Card>
			</main>
		</div>
	);
}
