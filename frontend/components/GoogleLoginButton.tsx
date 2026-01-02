import { Button } from "@heroui/react";

import { GoogleIcon } from "@/components/icons";

const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

const handleGoogleLogin = () => {
	window.location.href = `${apiUrl}/auth/google`; // Initiate OAuth
};

const GoogleLoginButton = () => {
	return (
		<div className="space-y-4 text-center">
			<Button
				className="w-full bg-white border-gray-300 text-gray-700"
				startContent={<GoogleIcon size={20} />}
				variant="bordered"
				onPress={handleGoogleLogin}
			>
				Sign in with Google
			</Button>
		</div>
	);
};

export default GoogleLoginButton;
