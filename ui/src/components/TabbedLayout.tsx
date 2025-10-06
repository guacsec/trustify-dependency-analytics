import {PageSection, PageSectionVariants, Tab, Tabs, TabTitleText,} from '@patternfly/react-core';
import {DepCompoundTable} from "./DepCompoundTable";
import {getSourceName, getSources, Report} from "../api/report";
import React, {useEffect, useRef} from 'react';
import {useAppContext} from '../App';
import {AnalyticsBrowser, AnalyticsBrowserSettings} from "@segment/analytics-next";

export const TabbedLayout = ({report}: { report: Report }) => {
  const appContext = useAppContext();
  const sources = getSources(report);
  const [activeTabKey, setActiveTabKey] = React.useState<string | number>(getSourceName(sources[0]));
  const [isTabsLightScheme] = React.useState<boolean>(true);

  const analytics = appContext.writeKey && appContext.writeKey.trim() !== '' ?
      AnalyticsBrowser.load({ writeKey: appContext.writeKey } as AnalyticsBrowserSettings) : null;
  const previousActiveTabKey = useRef<string | number>('');
  const identificationPerformedRef = useRef(false);

  useEffect(() => {
    if (!analytics) return;
    if (appContext.anonymousId != null) {
      analytics.setAnonymousId(appContext.anonymousId);
    }
    identificationPerformedRef.current = true;
    // eslint-disable-next-line
  }, []);

  useEffect(() => {
    if (!analytics) return;
    const handleActiveTabKeyUpdate = async (newActiveTabKey: string | number) => {
      if (newActiveTabKey !== previousActiveTabKey.current) {
        analytics.track("rhda.exhort.tab", {
          tabName: newActiveTabKey,
        });
        previousActiveTabKey.current = newActiveTabKey;
      }
    };
    handleActiveTabKeyUpdate(activeTabKey);
  }, [activeTabKey, analytics]);
  // Toggle currently active tab
  const handleTabClick = (
      event: React.MouseEvent<any> | React.KeyboardEvent | MouseEvent,
      tabIndex: string | number,
  ) => {
    setActiveTabKey(tabIndex);
  };

  const tabs = sources.map((source) => {
    const srcName = getSourceName(source);
    const vulnDeps = source.report.dependencies?.filter((dep) => dep.highestVulnerability)
    return (
      <Tab
        eventKey={srcName}
        title={<TabTitleText>{srcName}</TabTitleText>}
        aria-label={`${srcName} source`}
      >
        <PageSection variant={PageSectionVariants.default}>
          <DepCompoundTable name={srcName} dependencies={vulnDeps} />
        </PageSection>
      </Tab>
    );
  });

  return (
      <div>
        <Tabs
            activeKey={activeTabKey}
            onSelect={handleTabClick}
            aria-label="Providers"
            role="region"
            variant={isTabsLightScheme ? 'light300' : 'default'}
            isBox>
          {tabs}
        </Tabs>
      </div>
  );
};