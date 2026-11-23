'use client';

export function CloseButton({ onClose }: { onClose?: () => void }) {
  return (
    <button type="button" aria-label="Close dialog" onClick={onClose}>
      <svg aria-hidden="true" viewBox="0 0 10 10"><path d="M0 0L10 10" /></svg>
    </button>
  );
}
