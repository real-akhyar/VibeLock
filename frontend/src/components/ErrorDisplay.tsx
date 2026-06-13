import { AlertTriangle } from 'lucide-react';

interface ErrorDisplayProps {
  message: string;
  onRetry?: () => void;
}

export default function ErrorDisplay({ message, onRetry }: ErrorDisplayProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4">
      <div className="p-4 bg-red-900/30 rounded-full">
        <AlertTriangle className="w-8 h-8 text-red-400" />
      </div>
      <p className="text-red-400 text-sm max-w-md text-center">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="btn-secondary text-sm">
          Retry
        </button>
      )}
    </div>
  );
}