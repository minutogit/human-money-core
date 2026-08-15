import React, { useState, ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

interface AccordionSectionProps {
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  defaultOpen?: boolean;
  isOpen?: boolean;
  onToggle?: () => void;
  children: ReactNode;
}

export const AccordionSection: React.FC<AccordionSectionProps> = ({
  title,
  subtitle,
  icon,
  defaultOpen = false,
  isOpen,
  onToggle,
  children,
}) => {
  const [internalOpen, setInternalOpen] = useState(defaultOpen);

  const isControlled = isOpen !== undefined;
  const currentlyOpen = isControlled ? isOpen : internalOpen;

  const handleToggle = () => {
    if (onToggle) {
      onToggle();
    }
    if (!isControlled) {
      setInternalOpen((prev) => !prev);
    }
  };

  return (
    <div className={`accordion-section card ${currentlyOpen ? 'open' : ''}`}>
      <button
        type="button"
        className="accordion-header"
        onClick={handleToggle}
        aria-expanded={currentlyOpen}
      >
        <div className="accordion-header-left">
          {icon && <span className="accordion-icon">{icon}</span>}
          <div className="accordion-title-wrap">
            <h3 className="accordion-title">{title}</h3>
            {subtitle && <span className="accordion-subtitle">{subtitle}</span>}
          </div>
        </div>
        <ChevronDown
          size={18}
          className={`accordion-chevron ${currentlyOpen ? 'rotated' : ''}`}
        />
      </button>

      <div className={`accordion-content ${currentlyOpen ? 'expanded' : 'collapsed'}`}>
        <div className="accordion-body">{children}</div>
      </div>
    </div>
  );
};
