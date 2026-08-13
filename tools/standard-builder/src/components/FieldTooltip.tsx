import React, { useState, useRef, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { HelpCircle, Info, Sparkles, Shield, Lock, X } from 'lucide-react';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldExplanation } from '../i18n/types';

interface FieldTooltipProps {
  explanation: FieldExplanation;
  zone?: 'immutable' | 'mutable' | 'crypto';
  className?: string;
}

export const FieldTooltip: React.FC<FieldTooltipProps> = ({
  explanation,
  zone = 'immutable',
  className = '',
}) => {
  const { t } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const [coords, setCoords] = useState<{ top: number; left: number; width: number; maxHeight: number; placement: 'top' | 'bottom' }>({
    top: 0,
    left: 0,
    width: 360,
    maxHeight: 450,
    placement: 'bottom',
  });

  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  // Calculate dynamic floating position with viewport boundary clamping
  const updatePosition = useCallback(() => {
    if (!triggerRef.current) return;

    const triggerRect = triggerRef.current.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const padding = 12; // Min distance from viewport edges

    // Target width: min(380px, viewport - 2 * padding)
    const targetWidth = Math.min(380, viewportWidth - padding * 2);

    // Approximate height if not yet measured, or use measured height
    const popoverHeight = popoverRef.current
      ? popoverRef.current.offsetHeight
      : 320;

    // Determine vertical placement (top vs bottom)
    const spaceBelow = viewportHeight - triggerRect.bottom - padding;
    const spaceAbove = triggerRect.top - padding;

    let placement: 'top' | 'bottom' = 'bottom';
    let top = 0;
    let availableMaxHeight = 450;

    if (spaceBelow >= Math.min(popoverHeight, 260) || spaceBelow >= spaceAbove) {
      // Place below
      placement = 'bottom';
      top = triggerRect.bottom + 8;
      availableMaxHeight = Math.max(180, spaceBelow - 16);
    } else {
      // Place above
      placement = 'top';
      top = Math.max(padding, triggerRect.top - popoverHeight - 8);
      availableMaxHeight = Math.max(180, spaceAbove - 16);
    }

    // Determine horizontal placement (align with trigger center, clamp to screen bounds)
    const triggerCenterX = triggerRect.left + triggerRect.width / 2;
    let left = triggerCenterX - targetWidth / 2;

    // Clamp left edge
    if (left < padding) {
      left = padding;
    }
    // Clamp right edge
    if (left + targetWidth > viewportWidth - padding) {
      left = viewportWidth - padding - targetWidth;
    }

    setCoords({
      top,
      left,
      width: targetWidth,
      maxHeight: availableMaxHeight,
      placement,
    });
  }, []);

  // Update position when opened, or on resize/scroll
  useEffect(() => {
    if (!isOpen) return;

    updatePosition();

    const handleScrollOrResize = () => {
      updatePosition();
    };

    window.addEventListener('scroll', handleScrollOrResize, true);
    window.addEventListener('resize', handleScrollOrResize);

    return () => {
      window.removeEventListener('scroll', handleScrollOrResize, true);
      window.removeEventListener('resize', handleScrollOrResize);
    };
  }, [isOpen, updatePosition]);

  // Measure popover DOM size after render for pixel-perfect placement
  useEffect(() => {
    if (isOpen) {
      // Run once immediately and once on next frame after DOM paint
      updatePosition();
      const raf = requestAnimationFrame(updatePosition);
      return () => cancelAnimationFrame(raf);
    }
  }, [isOpen, updatePosition]);

  // Close on outside click or Escape key
  useEffect(() => {
    if (!isOpen) return;

    const handleOutsideClick = (e: MouseEvent | TouchEvent) => {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(e.target as Node) &&
        triggerRef.current &&
        !triggerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('touchstart', handleOutsideClick);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('touchstart', handleOutsideClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const getBadgeLabel = () => {
    switch (zone) {
      case 'immutable':
        return t.tooltipImmutableBadge;
      case 'mutable':
        return t.tooltipMutableBadge;
      case 'crypto':
        return t.tooltipCryptoBadge;
      default:
        return '';
    }
  };

  const getBadgeIcon = () => {
    switch (zone) {
      case 'immutable':
        return <Lock size={12} />;
      case 'mutable':
        return <Sparkles size={12} />;
      case 'crypto':
        return <Shield size={12} />;
      default:
        return <Info size={12} />;
    }
  };

  const popoverContent = isOpen && typeof document !== 'undefined' ? (
    createPortal(
      <div
        ref={popoverRef}
        className={`field-tooltip-popover portal-popover placement-${coords.placement} zone-${zone}`}
        style={{
          position: 'fixed',
          top: `${coords.top}px`,
          left: `${coords.left}px`,
          width: `${coords.width}px`,
          maxHeight: `${coords.maxHeight}px`,
          zIndex: 999999,
        }}
        onMouseEnter={() => setIsOpen(true)}
        onMouseLeave={() => setIsOpen(false)}
        role="tooltip"
      >
        <div className="tooltip-header">
          <div className="tooltip-title-wrap">
            <span className="tooltip-title">{explanation.tooltipTitle || explanation.label}</span>
            <span className={`tooltip-zone-badge badge-${zone}`}>
              {getBadgeIcon()}
              <span>{getBadgeLabel()}</span>
            </span>
          </div>
          <button
            type="button"
            className="tooltip-close-btn"
            onClick={() => setIsOpen(false)}
            aria-label="Schließen"
          >
            <X size={13} />
          </button>
        </div>

        <div className="tooltip-body-scrollable">
          {/* 1. Was ist das? */}
          {explanation.tooltipWhat && (
            <div className="tooltip-section">
              <div className="tooltip-section-header">
                <span className="tooltip-bullet blue">1</span>
                <strong>{t.tooltipWhatLabel}</strong>
              </div>
              <p className="tooltip-text">{explanation.tooltipWhat}</p>
            </div>
          )}

          {/* 2. Wozu & Warum? */}
          {explanation.tooltipWhy && (
            <div className="tooltip-section">
              <div className="tooltip-section-header">
                <span className="tooltip-bullet emerald">2</span>
                <strong>{t.tooltipWhyLabel}</strong>
              </div>
              <p className="tooltip-text">{explanation.tooltipWhy}</p>
            </div>
          )}

          {/* 3. Auswirkung */}
          {explanation.tooltipImpact && (
            <div className="tooltip-section">
              <div className="tooltip-section-header">
                <span className="tooltip-bullet amber">3</span>
                <strong>{t.tooltipImpactLabel}</strong>
              </div>
              <p className="tooltip-text impact-text">{explanation.tooltipImpact}</p>
            </div>
          )}
        </div>
      </div>,
      document.body
    )
  ) : null;

  return (
    <div className={`field-tooltip-container ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        className={`field-tooltip-trigger ${isOpen ? 'active' : ''} zone-${zone}`}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setIsOpen((prev) => !prev);
        }}
        onMouseEnter={() => setIsOpen(true)}
        onMouseLeave={(e) => {
          const related = e.relatedTarget as Node | null;
          if (popoverRef.current && related && popoverRef.current.contains(related)) {
            return;
          }
          setIsOpen(false);
        }}
        aria-expanded={isOpen}
        aria-label={`Erklärung zu ${explanation.label || explanation.tooltipTitle}`}
        title="Erklärung anzeigen"
      >
        <HelpCircle size={14} />
      </button>

      {popoverContent}
    </div>
  );
};
