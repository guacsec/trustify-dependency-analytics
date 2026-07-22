import React from 'react';
import { Button, Label, Popover } from '@patternfly/react-core';
import { AdvisoryRemediation, RemediationCategory, RemediationInfo, AdvisoryInfo, VersionRange } from '../api/report';
import { useAppContext } from '../App';
import { advisoryLink } from '../utils/utils';
import { formatRange, compareVersions } from '../utils/version';

interface AdvisoryRemediationsProps {
  advisories: AdvisoryRemediation[];
  vulnerabilityTitle?: string;
}

interface AdvisoryDetail {
  advisory?: AdvisoryInfo;
  status?: string;
  remediations: RemediationInfo[];
}

interface FixedInEntry {
  version: string;
  ranges: VersionRange[];
  advisoryDetails: AdvisoryDetail[];
  categories: RemediationCategory[];
}

const categoryLabels: Record<RemediationCategory, string> = {
  VENDOR_FIX: 'Vendor Fix',
  WORKAROUND: 'Workaround',
  MITIGATION: 'Mitigation',
  NO_FIX_PLANNED: 'No Fix Planned',
  NONE_AVAILABLE: 'None Available',
  WILL_NOT_FIX: 'Will Not Fix',
};

const categoryColors: Partial<Record<RemediationCategory, 'blue' | 'green' | 'orange' | 'red' | 'grey'>> = {
  VENDOR_FIX: 'blue',
  WORKAROUND: 'orange',
  MITIGATION: 'orange',
  NO_FIX_PLANNED: 'red',
  NONE_AVAILABLE: 'grey',
  WILL_NOT_FIX: 'red',
};

const getUniqueCategories = (remediations: RemediationInfo[]): RemediationCategory[] => {
  const categories = remediations
    .map(r => r.category)
    .filter((c): c is RemediationCategory => !!c);
  return categories.filter((c, i, arr) => arr.indexOf(c) === i);
};

const isSameRange = (a: VersionRange, b: VersionRange): boolean =>
  a.lowVersion === b.lowVersion &&
  a.highVersion === b.highVersion &&
  a.lowInclusive === b.lowInclusive &&
  a.highInclusive === b.highInclusive &&
  a.versionSchemeId === b.versionSchemeId;

function buildFixedInEntries(advisories: AdvisoryRemediation[]): FixedInEntry[] {
  const grouped = new Map<string, { ranges: VersionRange[]; advisoryDetails: AdvisoryDetail[]; categories: RemediationCategory[] }>();

  advisories.forEach(adv => {
    const ranges = adv.versionRanges || [];
    const remediations = adv.remediations || [];
    const detail: AdvisoryDetail = { advisory: adv.advisory, status: adv.status, remediations };

    const rangeVersions = ranges
      .filter(r => r.highVersion && !r.highInclusive)
      .map(r => r.highVersion as string);
    const uniqueRangeVersions = rangeVersions.filter((v, i, arr) => arr.indexOf(v) === i);

    const versions = uniqueRangeVersions.length > 0
      ? uniqueRangeVersions
      : [adv.fixedIn || ''];

    versions.forEach(version => {
      const matchingRanges = uniqueRangeVersions.length > 0
        ? ranges.filter(r => r.highVersion === version && !r.highInclusive)
        : ranges;

      const group = grouped.get(version);
      if (group) {
        group.advisoryDetails.push(detail);
        for (const r of matchingRanges) {
          if (!group.ranges.some(existing => isSameRange(existing, r))) {
            group.ranges.push(r);
          }
        }
        for (const cat of getUniqueCategories(remediations)) {
          if (!group.categories.includes(cat)) {
            group.categories.push(cat);
          }
        }
      } else {
        grouped.set(version, {
          ranges: [...matchingRanges],
          advisoryDetails: [detail],
          categories: getUniqueCategories(remediations),
        });
      }
    });
  });

  const entries: FixedInEntry[] = Array.from(grouped.entries()).map(([version, group]) => ({
    version,
    ranges: group.ranges,
    advisoryDetails: group.advisoryDetails,
    categories: group.categories,
  }));

  return entries.sort((a, b) => {
    if (!a.version) return 1;
    if (!b.version) return -1;
    return compareVersions(a.version, b.version);
  });
}

export const AdvisoryRemediations: React.FC<AdvisoryRemediationsProps> = ({ advisories, vulnerabilityTitle }) => {
  const appData = useAppContext();
  const entries = buildFixedInEntries(advisories);

  return (
    <div style={{ marginTop: '4px' }}>
      {entries.map((entry, index) => {
        const firstAdvisoryId = entry.advisoryDetails[0]?.advisory?.id || `Advisory ${index + 1}`;

        const popoverBody = (
          <div>
            {entry.ranges.length > 0 && (
              <div style={{ marginTop: '4px' }}>
                <strong>Affected range{entry.ranges.length > 1 ? 's' : ''}:</strong>
                {entry.ranges.map((range, i) => (
                  <div key={i}>{formatRange(range)}</div>
                ))}
              </div>
            )}
            {entry.advisoryDetails.map((detail, di) => {
              const advUrl = detail.advisory?.url
                ? advisoryLink(detail.advisory.url, appData)
                : undefined;
              const advId = detail.advisory?.id || `Advisory ${di + 1}`;
              return (
                <div key={di} style={{ marginTop: di === 0 ? '8px' : '12px', paddingTop: di > 0 ? '8px' : undefined, borderTop: di > 0 ? '1px solid var(--pf-t--global--border--color--default)' : undefined }}>
                  <p style={{ fontWeight: 600 }}>
                    {advUrl ? (
                      <a href={advUrl} target="_blank" rel="noreferrer">{advId}</a>
                    ) : (
                      advId
                    )}
                  </p>
                  {detail.status && (
                    <p><strong>Status:</strong> {detail.status}</p>
                  )}
                  {detail.remediations.length > 0 && (
                    <div style={{ marginTop: '4px' }}>
                      <strong>Remediation{detail.remediations.length > 1 ? 's' : ''}:</strong>
                      {detail.remediations.map((rem, ri) => {
                        const catLabel = rem.category ? categoryLabels[rem.category] ?? rem.category : 'Remediation';
                        const isRedundant = vulnerabilityTitle && rem.details && rem.details.trim() === vulnerabilityTitle.trim();
                        const remUrl = rem.url ? advisoryLink(rem.url, appData) : undefined;
                        return (
                          <div key={ri}>
                            <strong>{catLabel}</strong>
                            {rem.details && !isRedundant && (
                              <>
                                {': '}
                                {remUrl ? (
                                  <a href={remUrl} target="_blank" rel="noreferrer">{rem.details}</a>
                                ) : (
                                  rem.details
                                )}
                              </>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );

        const categoryChips = entry.categories.map((cat, i) => {
          const label = categoryLabels[cat] ?? cat;
          const color = categoryColors[cat] || 'grey';
          return (
            <Label key={i} isCompact color={color} style={{ marginLeft: i === 0 && entry.version ? '6px' : i > 0 ? '4px' : undefined }}>
              {label}
            </Label>
          );
        });

        return (
          <div key={`${entry.version || firstAdvisoryId}-${index}`} style={{ marginBottom: index < entries.length - 1 ? '6px' : undefined }}>
            <Popover
              headerContent={<strong>{entry.version ? `Fixed in ${entry.version}` : firstAdvisoryId}</strong>}
              bodyContent={popoverBody}
            >
              <Button variant="link" isInline style={{ fontWeight: 500 }}>
                {entry.version || (entry.categories.length === 0 ? firstAdvisoryId : null)}
              </Button>
            </Popover>
            {categoryChips}
          </div>
        );
      })}
    </div>
  );
};
