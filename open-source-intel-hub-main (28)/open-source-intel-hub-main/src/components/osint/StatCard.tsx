import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  variant?: "default" | "primary" | "warning" | "danger";
  className?: string;
}

const variantStyles = {
  default: "border-border",
  primary: "border-primary/30 bg-primary/5",
  warning: "border-warning/30 bg-warning/5",
  danger: "border-destructive/30 bg-destructive/5",
};

const iconStyles = {
  default: "text-primary bg-primary/10",
  primary: "text-primary bg-primary/20",
  warning: "text-warning bg-warning/20",
  danger: "text-destructive bg-destructive/20",
};

export function StatCard({ title, value, icon: Icon, trend, variant = "default", className }: StatCardProps) {
  return (
    <div
      className={cn(
        "card-cyber p-4 relative overflow-hidden group transition-all duration-300 hover:border-primary/50",
        variantStyles[variant],
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="text-2xl font-mono font-bold text-foreground">{value}</p>
          {trend && (
            <p className={cn(
              "text-xs font-medium",
              trend.value > 0 ? "text-success" : trend.value < 0 ? "text-destructive" : "text-muted-foreground"
            )}>
              {trend.value > 0 ? "+" : ""}{trend.value}% {trend.label}
            </p>
          )}
        </div>
        <div className={cn("p-2 rounded-lg transition-transform duration-300 group-hover:scale-110", iconStyles[variant])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      
      {/* Decorative corner glow */}
      <div className="absolute -top-10 -right-10 w-20 h-20 bg-primary/10 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
    </div>
  );
}
