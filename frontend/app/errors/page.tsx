"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";

import GoogleLoginButton from "@/components/GoogleLoginButton";

// Wrapper component that uses useSearchParams
function ErrorContent() {
	const searchParams = useSearchParams();
	const [errorMessage, setErrorMessage] = useState<React.ReactNode>("Something went wrong!");
	const [debugInfo, setDebugInfo] = useState<string>("");
	const [errorType, setErrorType] = useState<string>("");
	const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

	useEffect(() => {
		try {
			// Debugging information
			const msgParam = searchParams.get("message");
			setDebugInfo(`Error param: ${msgParam}`);

			// Get current time and timezone for error reporting
			const now = new Date();
			const timeString = now.toString();
			const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

			// Create email body for support
			const emailBody = encodeURIComponent(
				`Error: ${msgParam}\n` +
					`Time of error: ${timeString}\n` +
					`Timezone: ${timezone}\n` +
					`Browser: ${navigator.userAgent}\n\n` +
					`Please help me resolve this issue.\n\n` +
					`Thank you!`
			);

			// Store the error type for conditional rendering
			setErrorType(msgParam || "");

			// Rest of your existing code...

			if (msgParam === "permissions_error") {
				setErrorMessage("When Google asks for permissions, please make sure to check all the boxes.");
			} else if (msgParam === "credentials_error") {
				setErrorMessage(
					<>
						Failed to fetch credentials from Google. Please{" "}
						<a
							className="text-blue-600 hover:underline font-semibold"
							href={`mailto:help@justajobapp.com?subject=Google%20Credentials%20Error&body=${emailBody}`}
						>
							email our support team
						</a>{" "}
					</>
				);
			} else if (msgParam === "session_mismatch") {
				setErrorMessage(
					<>
						Your security session has expired or is invalid. This can happen if the login process took too
						long. Please try logging in again.
					</>
				);
			} else if (msgParam === "account_inactive") {
				setErrorMessage(
					<>
						It looks like you are trying to login with an unregistered account. Please{" "}
						<a
							className="text-blue-600 hover:underline font-semibold"
							href={`mailto:help@justajobapp.com?subject=Inactive%20Account%20Error&body=${emailBody}`}
						>
							email our support team
						</a>{" "}
					</>
				);
			} else {
				setErrorMessage(
					<>
						Uh oh, sorry about that. Please{" "}
						<a
							className="text-blue-600 hover:underline font-semibold"
							href={`mailto:help@justajobapp.com?subject=Login%20Error&body=${emailBody}`}
						>
							email our support team
						</a>{" "}
					</>
				);
			}
		} catch (err) {
			setErrorMessage(`Error page encountered an error: ${err instanceof Error ? err.message : String(err)}`);
		}
	}, [searchParams]);

	const handleTryAgain = () => {
		window.location.href = `${apiUrl}/auth/google`;
	};

	return (
		<div className="flex flex-col items-center justify-center min-h-screen p-6">
			<h2 className="text-2xl font-bold mb-4">Error Occurred</h2>
			<div className="text-lg mb-6">{errorMessage}</div>

			{process.env.NODE_ENV === "development" && (
				<div className="bg-gray-100 p-4 mb-6 rounded text-sm text-gray-700">
					<pre>{debugInfo}</pre>
				</div>
			)}

			{/* Only show the login button for permissions_error */}
			{(errorType === "permissions_error" || errorType === "session_mismatch") && <GoogleLoginButton />}

			<a className="mt-4 text-blue-600 hover:underline" href="/">
				Return to home page
			</a>
		</div>
	);
}

// Main page component with Suspense
export default function ErrorPage() {
	return (
		<Suspense fallback={<div className="flex items-center justify-center min-h-screen">Loading...</div>}>
			<ErrorContent />
		</Suspense>
	);
}
