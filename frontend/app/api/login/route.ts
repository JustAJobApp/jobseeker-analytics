import { NextResponse } from "next/server";

export async function GET() {
	const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
	// Redirect to backend login endpoint
	return NextResponse.redirect(`${apiUrl}/auth/google`);
}
