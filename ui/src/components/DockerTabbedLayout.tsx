import React, {useEffect, useMemo} from 'react';
import {Grid, GridItem, PageSection, PageSectionVariants, Tab, Tabs, TabTitleText,} from '@patternfly/react-core';
import {SummaryCard} from '../components/SummaryCard';
import {TabbedLayout} from "../components/TabbedLayout";
import {ReportErrorAlert} from '../components/ReportErrorAlert';
import {ReportMap} from '../api/report';
import {constructImageName} from '../utils/utils';

export const DockerTabbedLayout = ({report}: { report: ReportMap }) => {

  const sortedEntries = useMemo(
    () => Object.entries(report).sort(([a], [b]) => a.localeCompare(b)),
    [report]
  );

  const [activeTabKey, setActiveTabKey] = React.useState<string | number>(
    sortedEntries[0]?.[0] || ''
  );
  const [isTabsLightScheme] = React.useState<boolean>(true);

  useEffect(() => {
    const firstKey = sortedEntries[0]?.[0] || '';
    setActiveTabKey((prev) => {
      const validKeys = new Set(sortedEntries.map(([k]) => k));
      return validKeys.has(String(prev)) ? prev : firstKey;
    });
  }, [sortedEntries]);

  const handleTabClick = (
    event: React.MouseEvent<any> | React.KeyboardEvent | MouseEvent,
    tabIndex: string | number,
  ) => {
    setActiveTabKey(tabIndex);
  };

  const tabs = sortedEntries.map(([key, reportValue]) => {
    return (
      <Tab
        eventKey={key}
        title={<TabTitleText>{constructImageName(key)}</TabTitleText>} // Use the map key as title
        aria-label={`${key} source`}
      >
        <ReportErrorAlert report={reportValue} />
        <PageSection variant={PageSectionVariants.light}>
          <Grid hasGutter>
            <GridItem>
              <SummaryCard report={reportValue} isReportMap={true} purl={key}/>
            </GridItem>
          </Grid>
        </PageSection>
        <PageSection variant={PageSectionVariants.default}>
          <TabbedLayout report={reportValue} />
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