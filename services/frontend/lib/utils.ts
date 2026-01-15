import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_COLORS = {
  CRITICAL: "text-red-500 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-500 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  LOW: "text-blue-500 bg-blue-500/10 border-blue-500/20",
  INFO: "text-zinc-500 bg-zinc-500/10 border-zinc-500/20",
} as const;