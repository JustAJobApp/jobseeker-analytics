import { Button } from "@heroui/react";
import posthog from "posthog-js";

import { GoogleIcon } from "@/components/icons";

const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

interface GoogleSignupButtonProps {
	marketingConsent: boolean;
}

const GoogleSignupButton = ({ marketingConsent }: GoogleSignupButtonProps) => {
	const handleGoogleSignup = () => {
		posthog.capture("signup_started", { method: "google", marketing_consent: marketingConsent });
		window.location.href = `${apiUrl}/auth/google/signup?marketing_consent=${marketingConsent}`;
	};

	return (
		<div className="space-y-4 text-center">
			<Button
				className="w-full bg-white border-gray-300 text-gray-700"
				startContent={<GoogleIcon size={20} />}
				variant="bordered"
				onPress={handleGoogleSignup}
			>
				Continue with Google
			</Button>
		</div>
	);
};

export default GoogleSignupButton;
