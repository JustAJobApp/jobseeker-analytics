// frontend/app/login/page.tsx

"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Input, Button, Card, CardBody, CardHeader, Link } from "@heroui/react";

import { Navbar } from "@/components/navbar";
import GoogleLoginButton from "@/components/GoogleLoginButton";
import { checkAuth } from "@/utils/auth";
import { siteConfig } from "@/config/site";

export default function LoginPage() {
	const [email, setEmail] = useState("");
	const [code, setCode] = useState("");
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
			const response = await fetch(`${apiUrl}/billing/promos/${code}?email=${encodeURIComponent(email)}`, {
				method: "GET",
				credentials: "include"
			});
			const data = await response.json();
			if (data.status_code == 200) {
				setIsVerified(true);
				setError("");
			} else {
				setIsVerified(false);
				setError("Invalid access code or email. Please check your credentials and try again.");
			}
		} catch {
			setError("Code verification failed. Please try again.");
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="flex flex-col min-h-screen">
			<Navbar />
			<main
				aria-label="Login page"
				className="flex-grow flex items-center justify-center bg-background p-4 sm:p-6 md:p-8"
				role="main"
			>
				<Card aria-label="Login form" className="max-w-md w-full shadow-lg" role="region">
					<CardHeader className="flex flex-col gap-2 items-center pt-8 pb-4 px-6">
						<h1 className="text-3xl font-bold text-foreground">Welcome!</h1>
						{!isVerified && (
							<p className="text-sm text-default-500 text-center">
								If you need help, email{" "}
								<Link
									isExternal
									aria-label="Contact support via email"
									color="primary"
									href="mailto:help@justajobapp.com?subject=Beta%20Login%20Page%20Help"
									underline="hover"
								>
									help@justajobapp.com
								</Link>
							</p>
						)}
					</CardHeader>
					<CardBody className="pb-8 px-6">
						{isVerified == false ? (
							<form
								aria-label="Beta access verification form"
								className="space-y-5"
								onSubmit={handleVerifyEmail}
							>
								{error && (
									<div
										aria-live="polite"
										className="p-3 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800"
										role="alert"
									>
										<p className="text-sm text-danger-600 dark:text-danger-400">{error}</p>
									</div>
								)}
								<Input
									required
									aria-invalid={error ? "true" : "false"}
									aria-label="Email address for beta access"
									aria-required="true"
									autoComplete="email"
									classNames={{
										input: "text-foreground",
										label: "text-foreground"
									}}
									color="default"
									label="Email Address"
									placeholder="your.email@example.com"
									type="email"
									value={email}
									variant="bordered"
									onChange={(e) => setEmail(e.target.value)}
								/>
								<Input
									required
									aria-invalid={error ? "true" : "false"}
									aria-label="Beta access code"
									aria-required="true"
									autoComplete="off"
									classNames={{
										input: "text-foreground",
										label: "text-foreground"
									}}
									color="default"
									label="Access Code"
									placeholder="ABC-123"
									type="text"
									value={code}
									variant="bordered"
									onChange={(e) => setCode(e.target.value)}
								/>
								<Button
									aria-label="Continue to sign in"
									className="w-full font-semibold"
									color="primary"
									isLoading={loading}
									size="lg"
									type="submit"
								>
									Continue
								</Button>
								<p className="text-sm text-default-500 text-center pt-2">
									Not in the official beta?{" "}
									<Link
										isExternal
										aria-label="Join the waitlist"
										color="primary"
										href={siteConfig.links.waitlist}
										underline="hover"
									>
										Join the waitlist
									</Link>
								</p>
							</form>
						) : (
							<div className="space-y-4">
								<div
									aria-live="polite"
									className="p-3 rounded-lg bg-success-50 dark:bg-success-900/20 border border-success-200 dark:border-success-800"
									role="status"
								>
									<p className="text-sm text-success-600 dark:text-success-400 text-center">
										Email verified! Please sign in with Google to continue.
									</p>
								</div>
								<GoogleLoginButton />
							</div>
						)}
					</CardBody>
				</Card>
			</main>
		</div>
	);
}
