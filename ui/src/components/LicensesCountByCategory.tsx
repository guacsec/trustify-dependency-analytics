import React from 'react';
import { FlexItem, Icon } from '@patternfly/react-core';
import { LicenseInfo } from '../api/report';
import SecurityIcon from '@patternfly/react-icons/dist/esm/icons/security-icon';
import {
  CATEGORY_COLORS,
  CATEGORY_SORT_ORDER,
} from '../constants/licenseCategories';

export {
  CATEGORY_COLORS,
  CATEGORY_LABELS,
  getCategoryLabel,
  getCategoryColor,
  CATEGORY_SORT_ORDER,
  getCategorySortIndex,
} from '../constants/licenseCategories';

const CATEGORY_ORDER = CATEGORY_SORT_ORDER;

function countByCategory(evidence: LicenseInfo[]): Record<string, number> {
  const counts: Record<string, number> = {
    PERMISSIVE: 0,
    WEAK_COPYLEFT: 0,
    STRONG_COPYLEFT: 0,
    UNKNOWN: 0,
  };
  evidence?.forEach((info) => {
    const cat = (info.category || 'UNKNOWN').toUpperCase().replace(/-/g, '_');
    if (counts.hasOwnProperty(cat)) {
      counts[cat]++;
    } else {
      counts.UNKNOWN++;
    }
  });
  return counts;
}

function countByIdentifierCategory(evidence: LicenseInfo[]): Record<string, number> {
  const counts: Record<string, number> = {
    PERMISSIVE: 0,
    WEAK_COPYLEFT: 0,
    STRONG_COPYLEFT: 0,
    UNKNOWN: 0,
  };
  evidence?.forEach((info) => {
    (info.identifiers || []).forEach((id) => {
      const cat = (id.category || 'UNKNOWN').toUpperCase().replace(/-/g, '_');
      if (counts.hasOwnProperty(cat)) {
        counts[cat]++;
      } else {
        counts.UNKNOWN++;
      }
    });
  });
  return counts;
}

export const LicensesCountByCategory = ({
  evidence = [],
  countBy = 'evidence',
}: {
  evidence: LicenseInfo[];
  /** 'evidence': count by each evidence's category; 'identifiers': count by each identifier's category across all evidences */
  countBy?: 'evidence' | 'identifiers';
}) => {
  const counts = countBy === 'identifiers' ? countByIdentifierCategory(evidence) : countByCategory(evidence);

  return (
    <FlexItem>
      {CATEGORY_ORDER.map(
        (cat) =>
          counts[cat] > 0 && (
            <React.Fragment key={cat}>
              <Icon isInline>
                <SecurityIcon style={{fill: CATEGORY_COLORS[cat], height: '13px'}} />
              </Icon>
              &nbsp;
              {counts[cat]}&nbsp;
            </React.Fragment>
          )
      )}
    </FlexItem>
  );
};
