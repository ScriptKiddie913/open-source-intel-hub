import { cn } from "@/lib/utils";
import { Activity, CheckCircle2, XCircle, AlertCircle } from "lucide-react";

type APIStatus = "online" | "offline" | "rate_limited" | "checking";

interface APIStatusIndicatorProps {
  name: string;
  status: APIStatus;
  lastCheck?: Date;
  className?: string;
}

const statusConfig: Record<APIStatus, { icon: typeof Activity; label: string; className: string }> = {
  online: {
    icon: CheckCircle2,
    label: "Online",
    className: "text-success bg-success/10 border-success/30",
  },
  offline: {
    icon: XCircle,
    label: "Offline",
    className: "text-destructive bg-destructive/10 border-destructive/30",
  },
  rate_limited: {
    icon: AlertCircle,
    label: "Rate Limited",
    className: "text-warning bg-warning/10 border-warning/30",
  },
  checking: {
    icon: Activity,
    label: "Checking",
    className: "text-muted-foreground bg-muted border-border animate-pulse",
  },
};

export function APIStatusIndicator({ name, status, lastCheck, className }: APIStatusIndicatorProps) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "flex items-center justify-between p-3 rounded-lg border",
        config.className,
        className
      )}
    >
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4" />
        <span className="font-medium text-sm">{name}</span>
      </div>
      <div className="text-right">
        <span className="text-xs font-mono">{config.label}</span>
        {lastCheck && (
          <p className="text-xs text-muted-foreground">
            {new Date(lastCheck).toLocaleTimeString()}
          </p>
        )}
      </div>
    </div>
  );
}
