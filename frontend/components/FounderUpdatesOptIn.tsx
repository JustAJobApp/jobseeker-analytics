"use client";

import { Checkbox } from "@heroui/react";

interface Props {
	checked: boolean;
	onChange: (checked: boolean) => void;
}

export default function FounderUpdatesOptIn({ checked, onChange }: Props) {
	return (
		<Checkbox
			classNames={{
				base: "items-start max-w-full",
				label: "text-sm text-gray-600 dark:text-gray-400"
			}}
			isSelected={checked}
			size="sm"
			onValueChange={onChange}
		>
			Get behind-the-scenes email updates from the founder. Cat pictures are just as likely as
			screenshots of features I&apos;m thinking about.
		</Checkbox>
	);
}
