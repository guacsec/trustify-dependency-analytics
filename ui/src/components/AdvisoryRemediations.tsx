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

interface FixedInEntry {
  version: string;
  ranges: VersionRange[];
  advisory?: AdvisoryInfo;
  status?: string;
  remediations: RemediationInfo[];
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

function buildFixedInEntries(advisories: AdvisoryRemediation[]): FixedInEntry[] {
  const entries: FixedInEntry[] = [];

  advisories.forEach(adv => {
    const ranges = adv.versionRanges || [];
    const remediations = adv.remediations || [];
    const categories = getUniqueCategories(remediations);

    const rangeVersions = ranges
      .filter(r => r.highVersion && !r.highInclusive)
      .map(r => r.highVersion as string);
    const uniqueRangeVersions = rangeVersions.filter((v, i, arr) => arr.indexOf(v) === i);

    if (uniqueRangeVersions.length > 0) {
      uniqueRangeVersions.forEach(version => {
        const matchingRanges = ranges.filter(r => r.highVersion === version && !r.highInclusive);
        entries.push({
          version,
          ranges: matchingRanges,
          advisory: adv.advisory,
          status: adv.status,
          remediations,
          categories,
        });
      });
    } else if (adv.fixedIn) {
      entries.push({
        version: adv.fixedIn,
        ranges,
        advisory: adv.advisory,
        status: adv.status,
        remediations,
        categories,
      });
    } else {
      entries.push({
        version: '',
        ranges,
        advisory: adv.advisory,
        status: adv.status,
        remediations,
        categories,
      });
    }
  });

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
        const advisoryUrl = entry.advisory?.url
          ? advisoryLink(entry.advisory.url, appData)
          : undefined;
        const advisoryId = entry.advisory?.id || `Advisory ${index + 1}`;

        const popoverBody = (
          <div>
            {entry.status && (
              <p><strong>Status:</strong> {entry.status}</p>
            )}
            {entry.version && (
              <p><strong>Fixed in:</strong> {entry.version}</p>
            )}
            {entry.ranges.length > 0 && (
              <div style={{ marginTop: '4px' }}>
                <strong>Affected range{entry.ranges.length > 1 ? 's' : ''}:</strong>
                {entry.ranges.map((range, i) => (
                  <div key={i}>{formatRange(range)}</div>
                ))}
              </div>
            )}
            {entry.remediations.length > 0 && (
              <div style={{ marginTop: '4px' }}>
                <strong>Remediation{entry.remediations.length > 1 ? 's' : ''}:</strong>
                {entry.remediations.map((rem, i) => {
                  const catLabel = rem.category ? categoryLabels[rem.category] ?? rem.category : 'Remediation';
                  const isRedundant = vulnerabilityTitle && rem.details && rem.details.trim() === vulnerabilityTitle.trim();
                  const remUrl = rem.url ? advisoryLink(rem.url, appData) : undefined;
                  return (
                    <div key={i}>
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
            {advisoryUrl && (
              <p style={{ marginTop: '4px' }}>
                <a href={advisoryUrl} target="_blank" rel="noreferrer">
                  {entry.advisory?.title || advisoryId}
                </a>
              </p>
            )}
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
          <div key={`${entry.advisory?.id ?? 'adv'}-${entry.version || index}`} style={{ marginBottom: index < entries.length - 1 ? '6px' : undefined }}>
            <Popover
              headerContent={<strong>{entry.version ? `Fixed in ${entry.version}` : advisoryId}</strong>}
              bodyContent={popoverBody}
            >
              <Button variant="link" isInline style={{ fontWeight: 500 }}>
                {entry.version || (entry.categories.length === 0 ? advisoryId : null)}
              </Button>
            </Popover>
            {categoryChips}
          </div>
        );
      })}
    </div>
  );
};
