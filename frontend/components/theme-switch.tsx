"use client";

import { FC } from "react";
import { VisuallyHidden } from "@react-aria/visually-hidden";
import { SwitchProps, useSwitch } from "@heroui/react";
import { useTheme } from "next-themes";
import { useIsSSR } from "@react-aria/ssr";
import clsx from "clsx";

import { SunFilledIcon, MoonFilledIcon } from "@/components/icons";

export interface ThemeSwitchProps {
	className?: string;
	classNames?: SwitchProps["classNames"];
	children?: React.ReactNode;
}

export const ThemeSwitch: FC<ThemeSwitchProps> = ({ className, classNames, children }) => {
	const { theme, setTheme } = useTheme();
	const isSSR = useIsSSR();

	const onChange = () => {
		if (theme === "dark") {
			setTheme("light");
		} else {
			setTheme("dark");
		}
		// Blur the element so keyboard shortcuts work after theme switch
		if (document.activeElement instanceof HTMLElement) {
			document.activeElement.blur();
		}
	};

	const { Component, slots, isSelected, getBaseProps, getInputProps, getWrapperProps } = useSwitch({
		isSelected: theme === "dark" || isSSR,
		"aria-label": `Switch to ${theme === "dark" || isSSR ? "light" : "dark"} mode`,
		onChange
	});

	const tooltipText = isSelected && !isSSR ? "Switch to light mode" : "Switch to dark mode";

	return (
		<div className="relative group px-2 py-1.5 border border-divider rounded-md text-default-500 hover:text-foreground hover:border-default-400 transition-colors block">
			<Component
				{...getBaseProps({
					className: clsx(
						"px-px transition-opacity hover:opacity-80 cursor-pointer",
						className,
						classNames?.base
					)
				})}
			>
				<VisuallyHidden>
					<input {...getInputProps()} />
				</VisuallyHidden>
				<div
					{...getWrapperProps()}
					className={slots.wrapper({
						class: clsx(
							[
								"w-auto h-auto",
								"bg-transparent",
								"rounded-lg",
								"flex items-center justify-center gap-2", // Added gap for spacing
								"group-data-[selected=true]:bg-transparent",
								"!text-default-500",
								"pt-px",
								"px-0",
								"mx-0"
							],
							classNames?.wrapper
						)
					})}
				>
					<div data-testid="theme-switch-button">
						{!isSelected || isSSR ? <MoonFilledIcon size={22} /> : <SunFilledIcon size={22} />}
						{children && <span className="text-default-600">{children}</span>}
					</div>
				</div>
			</Component>
			<div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 dark:bg-gray-700 rounded opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 whitespace-nowrap z-50">
				{tooltipText}
			</div>
		</div>
	);
};
