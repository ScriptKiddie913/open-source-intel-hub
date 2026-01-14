import { cn } from "@/lib/utils";
import { ThreatLevel } from "@/types/osint";

interface ThreatBadgeProps {
  level: ThreatLevel;
  showLabel?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
}

const threatConfig: Record<ThreatLevel, { label: string; className: string; dotClass: string }> = {
  critical: {
    label: "Critical",
    className: "bg-destructive/20 text-destructive border-destructive/40",
    dotClass: "bg-destructive animate-pulse",
  },
  high: {
    label: "High",
    className: "bg-cyber-orange/20 text-cyber-orange border-cyber-orange/40",
    dotClass: "bg-cyber-orange animate-pulse",
  },
  medium: {
    label: "Medium",
    className: "bg-warning/20 text-warning border-warning/40",
    dotClass: "bg-warning",
  },
  low: {
    label: "Low",
    className: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/40",
    dotClass: "bg-cyber-cyan",
  },
  info: {
    label: "Info",
    className: "bg-muted text-muted-foreground border-border",
    dotClass: "bg-muted-foreground",
  },
};

const sizeConfig = {
  sm: "text-xs px-1.5 py-0.5",
  md: "text-xs px-2 py-1",
  lg: "text-sm px-3 py-1.5",
};

export function ThreatBadge({ level, showLabel = true, size = "md", className }: ThreatBadgeProps) {
  const config = threatConfig[level];
  
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border font-mono font-medium",
        config.className,
        sizeConfig[size],
        className
      )}
    >
      <span className={cn("w-1.5 h-1.5 rounded-full", config.dotClass)} />
      {showLabel && config.label}
    </span>
  );
}
