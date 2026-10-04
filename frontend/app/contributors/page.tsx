"use client";

import React from "react";
import { Card, CardBody, Avatar } from "@heroui/react";

import contributorsData from "../../data/contributors.json";

import { Navbar } from "@/components/navbar";
import { siteConfig } from "@/config/site";

interface Contributor {
	name: string;
	github: string;
	avatar: string;
	message: string;
	date: string;
}

export default function ContributorsPage() {
	return (
		<div className="flex flex-col">
			<Navbar />
			<main className="flex-grow">
				<div className="container mx-auto px-4 py-12">
					{/* Header */}
					<div className="text-center mb-12">
						<h1 className="text-4xl md:text-6xl font-bold text-gray-800 dark:text-white mb-4">
							Wall of Fame 🏆
						</h1>
						<p className="text-xl text-gray-600 dark:text-gray-300 max-w-2xl mx-auto mb-8">
							Meet the contributors who have helped build JustAJobApp. Each person here has left their
							mark on this project!
						</p>
						<a
							className="inline-flex items-center justify-center px-8 py-4 bg-gray-900 dark:bg-white text-white dark:text-gray-900 text-lg font-semibold rounded-lg hover:bg-gray-800 dark:hover:bg-gray-100 transition-colors"
							href={siteConfig.links.github}
							rel="noopener noreferrer"
							target="_blank"
						>
							<svg className="w-6 h-6 mr-2" fill="currentColor" viewBox="0 0 24 24">
								<path
									clipRule="evenodd"
									d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
									fillRule="evenodd"
								/>
							</svg>
							Contribute on GitHub
						</a>
					</div>

					{/* Contributors Grid */}
					<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-7xl mx-auto">
						{[...contributorsData]
							.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
							.map((contributor: Contributor, index: number) => (
								<Card
									key={contributor.github}
									isPressable
									className="hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2"
									onPress={() => window.open(`https://github.com/${contributor.github}`, "_blank")}
								>
									<CardBody className="text-center p-6">
										{/* Avatar */}
										<div className="flex justify-center mb-4">
											<Avatar
												showFallback
												className="w-24 h-24 text-large"
												name={contributor.name}
												size="lg"
												src={contributor.avatar}
											/>
										</div>

										{/* Name */}
										<h3 className="text-xl font-bold text-gray-800 dark:text-white mb-2">
											{contributor.name}
										</h3>

										{/* GitHub Username */}
										<p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
											@{contributor.github}
										</p>

										{/* Message */}
										<div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 mb-4">
											<p className="text-gray-700 dark:text-gray-300 italic">
												"{contributor.message}"
											</p>
										</div>

										{/* Date */}
										<p className="text-xs text-gray-400 dark:text-gray-500">
											Joined{" "}
											{new Date(contributor.date).toLocaleDateString("en-US", {
												year: "numeric",
												month: "long",
												day: "numeric"
											})}
										</p>
									</CardBody>
								</Card>
							))}
					</div>

					{/* Call to Action */}
					<div className="text-center mt-16">
						<div className="bg-white bg-background dark:bg-content1 rounded-2xl p-8 shadow-lg max-w-2xl mx-auto">
							<h2 className="text-2xl font-bold text-gray-800 dark:text-white mb-4">
								Want to join the Wall of Fame?
							</h2>
							<p className="text-gray-600 dark:text-gray-300 mb-6">
								Make your first contribution and get your profile added! Check out our{" "}
								<a
									className="text-blue-600 hover:text-blue-700 underline"
									href={siteConfig.links.contributorOnboarding}
									rel="noopener noreferrer"
									target="_blank"
								>
									contributor onboarding guide
								</a>{" "}
								to get started.
							</p>
							<a
								className="inline-flex items-center justify-center px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
								href={siteConfig.links.contributorOnboardingStep3}
								rel="noopener noreferrer"
								target="_blank"
							>
								In the guided install workshop? Click here!
							</a>
						</div>
					</div>
				</div>
			</main>
		</div>
	);
}
