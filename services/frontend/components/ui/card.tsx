import { cn } from "@/lib/utils";

export function Card({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("bg-white rounded-xl border border-slate-200 shadow-sm transition-all hover:border-indigo-100", className)} {...props}>
      {children}
    </div>
  );
}