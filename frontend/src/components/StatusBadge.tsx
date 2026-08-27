import React from 'react';

interface StatusBadgeProps {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'disabled' | 'BLOCK' | 'FLAG' | 'ALLOW';
  size?: 'sm' | 'md' | 'lg';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const getColors = () => {
    switch (status) {
      case 'healthy':
      case 'ALLOW':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'degraded':
      case 'FLAG':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'unhealthy':
      case 'BLOCK':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'disabled':
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const getDotColor = () => {
    switch (status) {
      case 'healthy':
      case 'ALLOW':
        return 'bg-emerald-400';
      case 'degraded':
      case 'FLAG':
        return 'bg-amber-400';
      case 'unhealthy':
      case 'BLOCK':
        return 'bg-rose-400';
      default:
        return 'bg-slate-400';
    }
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3 py-1.5',
  }[size];

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-medium border uppercase tracking-wider ${getColors()} ${sizeClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${getDotColor()} animate-pulse`} />
      {status}
    </span>
  );
};
