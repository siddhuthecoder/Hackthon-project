import { AlertCircle, Loader2 } from 'lucide-react';

export function LoadingState({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-sm text-muted-foreground">
      <Loader2 className="w-4 h-4 animate-spin" />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center gap-3 p-4 rounded-lg border border-destructive/30 bg-destructive/5 text-sm">
      <AlertCircle className="w-4 h-4 text-destructive shrink-0" />
      <span className="text-destructive flex-1">{message}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="text-xs underline text-muted-foreground hover:text-foreground">
          Retry
        </button>
      )}
    </div>
  );
}
