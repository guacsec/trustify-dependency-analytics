import {
  PageSection,
  PageSectionVariants,
  Tab,
  Tabs,
  TabTitleText,
} from '@patternfly/react-core';
import { DepCompoundTable } from './DepCompoundTable';
import { LicensesTable } from './LicensesTable';
import { getSourceName, getSources, Report } from '../api/report';
import React, { useEffect, useRef } from 'react';
import { useAppContext } from '../App';
import { AnalyticsBrowser, AnalyticsBrowserSettings } from '@segment/analytics-next';

const PRIMARY_VULN = 'vulnerabilities';
const PRIMARY_LICENSES = 'licenses';

export const TabbedLayout = ({ report }: { report: Report }) => {
  const appContext = useAppContext();
  const sources = getSources(report);
  const hasVuln = sources.length > 0;
  const hasLicenses = (report.licenses?.length ?? 0) > 0;

  const firstVulnKey = hasVuln ? getSourceName(sources[0]) : null;
  const firstLicenseKey = hasLicenses ? report.licenses![0].status.name : null;

  const [activePrimaryKey, setActivePrimaryKey] = React.useState<string | number>(
    hasVuln ? PRIMARY_VULN : PRIMARY_LICENSES
  );
  const [activeVulnKey, setActiveVulnKey] = React.useState<string | number>(firstVulnKey ?? 0);
  const [activeLicenseKey, setActiveLicenseKey] = React.useState<string | number>(
    firstLicenseKey ?? 0
  );

  const analytics =
    appContext.writeKey && appContext.writeKey.trim() !== ''
      ? AnalyticsBrowser.load({ writeKey: appContext.writeKey } as AnalyticsBrowserSettings)
      : null;
  const previousTrackedKey = useRef<string | number>('');

  useEffect(() => {
    if (!analytics) return;
    if (appContext.anonymousId != null) {
      analytics.setAnonymousId(appContext.anonymousId);
    }
  }, [analytics, appContext.anonymousId]);

  // Track the effective tab (primary + secondary) for analytics
  const effectiveTabKey =
    activePrimaryKey === PRIMARY_VULN ? activeVulnKey : activeLicenseKey;
  useEffect(() => {
    if (!analytics || effectiveTabKey === previousTrackedKey.current) return;
    analytics.track('rhda.exhort.tab', { tabName: effectiveTabKey });
    previousTrackedKey.current = effectiveTabKey;
  }, [analytics, effectiveTabKey]);

  const handlePrimarySelect = (
    _event: React.MouseEvent | React.KeyboardEvent | MouseEvent,
    tabKey: string | number
  ) => {
    setActivePrimaryKey(tabKey);
  };

  const handleVulnSelect = (
    _event: React.MouseEvent | React.KeyboardEvent | MouseEvent,
    tabKey: string | number
  ) => {
    setActiveVulnKey(tabKey);
  };

  const handleLicenseSelect = (
    _event: React.MouseEvent | React.KeyboardEvent | MouseEvent,
    tabKey: string | number
  ) => {
    setActiveLicenseKey(tabKey);
  };

  const primaryTabs: React.ReactElement[] = [];

  if (hasVuln) {
    primaryTabs.push(
      <Tab
        key={PRIMARY_VULN}
        eventKey={PRIMARY_VULN}
        title={<TabTitleText>Vulnerabilities</TabTitleText>}
        aria-label="Vulnerabilities"
      >
        <Tabs
          activeKey={activeVulnKey}
          onSelect={handleVulnSelect}
          isSecondary
          isBox
          variant="light300"
          aria-label="Vulnerability providers"
          role="region"
        >
          {sources.map((source) => {
            const srcName = getSourceName(source);
            const vulnDeps = source.report.dependencies?.filter((dep) => dep.highestVulnerability);
            return (
              <Tab
                key={srcName}
                eventKey={srcName}
                title={<TabTitleText>{srcName}</TabTitleText>}
                aria-label={`${srcName} source`}
              >
                <PageSection variant={PageSectionVariants.default}>
                  <DepCompoundTable name={srcName} dependencies={vulnDeps} />
                </PageSection>
              </Tab>
            );
          })}
        </Tabs>
      </Tab>
    );
  }

  if (hasLicenses) {
    primaryTabs.push(
      <Tab
        key={PRIMARY_LICENSES}
        eventKey={PRIMARY_LICENSES}
        title={<TabTitleText>Licenses</TabTitleText>}
        aria-label="Licenses"
      >
        <Tabs
          activeKey={activeLicenseKey}
          onSelect={handleLicenseSelect}
          isSecondary
          isBox
          variant="light300"
          aria-label="License providers"
          role="region"
        >
          {report.licenses!.map((license) => (
            <Tab
              key={license.status.name}
              eventKey={license.status.name}
              title={<TabTitleText>{license.status.name}</TabTitleText>}
              aria-label={`${license.status.name} source`}
            >
              <PageSection variant={PageSectionVariants.default}>
                <LicensesTable name={license.status.name} dependencies={license.packages} />
              </PageSection>
            </Tab>
          ))}
        </Tabs>
      </Tab>
    );
  }

  if (primaryTabs.length === 0) {
    return null;
  }

  return (
    <div>
      <Tabs
        activeKey={activePrimaryKey}
        onSelect={handlePrimarySelect}
        aria-label="Providers"
        role="region"
        variant="light300"
        isBox
      >
        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
        {primaryTabs as any}
      </Tabs>
    </div>
  );
};
