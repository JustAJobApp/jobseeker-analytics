// frontend/components/PrivacyFirst.tsx
"use client";

import { Card, CardBody } from "@heroui/react";
import { ShieldCheckIcon } from "@heroicons/react/24/solid";
import Link from "next/link";

export const PrivacyFirst = () => {
	return (
		<section className="bg-gray-50 dark:bg-gray-900/40 py-16">
			<div className="container mx-auto px-4 max-w-4xl">
				<div className="text-center mb-12">
					<h2 className="text-3xl font-bold tracking-tight sm:text-4xl">Privacy is Our Product</h2>
					<p className="mt-4 text-lg leading-8 text-gray-600 dark:text-gray-300">
						For a tool that reads your inbox, trust is everything. We are committed to Radical Transparency.
					</p>
				</div>
				<div className="grid gap-8 md:grid-cols-2">
					<Card className="p-6">
						<CardBody>
							<div className="flex items-center gap-4 mb-4">
								<ShieldCheckIcon className="h-8 w-8 text-emerald-500" />
								<h3 className="text-xl font-semibold">We Don't Read Your Emails</h3>
							</div>
							<p className="text-gray-600 dark:text-gray-300">
								We use a narrow search query for job-related messages only. If an email isn't from a
								known hiring platform or doesn't contain keywords like "application received," we ignore
								it.
							</p>
						</CardBody>
					</Card>
					<Card className="p-6">
						<CardBody>
							<div className="flex items-center gap-4 mb-4">
								<ShieldCheckIcon className="h-8 w-8 text-emerald-500" />
								<h3 className="text-xl font-semibold">Your Data is Not For Sale</h3>
							</div>
							<p className="text-gray-600 dark:text-gray-300">
								We use Google's paid Gemini API, which at the time of writing, contractually forbids
								them from using your data to train their models. Your data is yours, and it is never
								monetized.
							</p>
						</CardBody>
					</Card>
				</div>
				<div className="text-center mt-12 flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-8">
					<Link className="font-medium text-emerald-600 hover:text-emerald-500" href="/security">
						View our security audit &rarr;
					</Link>
					<Link className="font-medium text-emerald-600 hover:text-emerald-500" href="/faq">
						Read our full FAQ &rarr;
					</Link>
				</div>
			</div>
		</section>
	);
};
