import { cn } from "@/lib/utils";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  noPadding?: boolean;
}

export function GlassCard({ className, noPadding, children, ...props }: CardProps) {
  return (
    <div 
      className={cn(
        "bg-white rounded-xl border border-slate-200 shadow-soft transition-all duration-300 hover:border-indigo-100",
        !noPadding && "p-6",
        className
      )} 
      {...props}
    >
      {children}
    </div>
  );
}