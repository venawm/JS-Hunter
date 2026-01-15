import { cn } from "@/lib/utils";
import { Severity } from "@/lib/types";

const STYLES = {
  CRITICAL: "bg-red-50 text-red-700 border-red-100 ring-red-100",
  HIGH: "bg-orange-50 text-orange-700 border-orange-100 ring-orange-100",
  MEDIUM: "bg-amber-50 text-amber-700 border-amber-100 ring-amber-100",
  LOW: "bg-blue-50 text-blue-700 border-blue-100 ring-blue-100",
  INFO: "bg-slate-50 text-slate-700 border-slate-100 ring-slate-100",
};

export function SeverityBadge({ level }: { level: Severity }) {
  return (
    <span className={cn(
      "px-3 py-1 rounded-full text-[11px] font-bold uppercase tracking-wide border ring-1 ring-inset",
      STYLES[level] || STYLES.INFO
    )}>
      {level}
    </span>
  );
}