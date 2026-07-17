import React from 'react';
import { Button, Popover } from '@patternfly/react-core';
import { RemediationInfo, RemediationCategory } from '../api/report';
import { useAppContext } from '../App';
import { advisoryLink } from '../utils/utils';

interface RemediationDetailsProps {
  remediations: RemediationInfo[];
  vulnerabilityTitle?: string;
}

const categoryLabels: Record<RemediationCategory, string> = {
  VENDOR_FIX: 'Vendor Fix',
  WORKAROUND: 'Workaround',
  MITIGATION: 'Mitigation',
  NO_FIX_PLANNED: 'No Fix Planned',
  NONE_AVAILABLE: 'None Available',
  WILL_NOT_FIX: 'Will Not Fix',
};

const isRedundant = (rem: RemediationInfo, vulnerabilityTitle?: string): boolean => {
  if (!vulnerabilityTitle || !rem.details) {
    return false;
  }
  return rem.details.trim() === vulnerabilityTitle.trim();
};

const remediationKey = (rem: RemediationInfo, index: number): string => {
  const parts = [rem.advisory?.id, rem.category, rem.url].filter(Boolean);
  return parts.length > 0 ? parts.join('-') : `remediation-${index}`;
};

export const RemediationDetails: React.FC<RemediationDetailsProps> = ({ remediations, vulnerabilityTitle }) => {
  const appData = useAppContext();

  return (
    <>
      {remediations.map((rem, index) => {
        const label = rem.category
          ? categoryLabels[rem.category] ?? rem.category
          : 'Remediation';

        if (isRedundant(rem, vulnerabilityTitle)) {
          return (
            <div key={remediationKey(rem, index)}>
              <span>{label}</span>
            </div>
          );
        }

        const advisoryUrl = rem.advisory?.url
          ? advisoryLink(rem.advisory.url, appData)
          : undefined;

        if (rem.details) {
          const remUrl = rem.url ? advisoryLink(rem.url, appData) : undefined;

          const bodyContent = (
            <div>
              <p>
                {remUrl ? (
                  <a href={remUrl} target="_blank" rel="noreferrer noopener">
                    {rem.details}
                  </a>
                ) : (
                  rem.details
                )}
              </p>
              {advisoryUrl && (
                <p>
                  <a href={advisoryUrl} target="_blank" rel="noreferrer noopener">
                    {rem.advisory?.id || 'Advisory'}
                  </a>
                </p>
              )}
            </div>
          );

          return (
            <div key={remediationKey(rem, index)}>
              <Popover
                headerContent={<strong>{label}</strong>}
                bodyContent={bodyContent}
              >
                <Button variant="link" isInline>
                  {label}
                </Button>
              </Popover>
            </div>
          );
        }

        if (advisoryUrl) {
          return (
            <div key={remediationKey(rem, index)}>
              <a href={advisoryUrl} target="_blank" rel="noreferrer noopener">
                {label}
              </a>
            </div>
          );
        }

        return (
          <div key={remediationKey(rem, index)}>
            <span>{label}</span>
          </div>
        );
      })}
    </>
  );
};
