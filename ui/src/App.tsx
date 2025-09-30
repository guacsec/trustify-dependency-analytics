import {createContext, useContext} from 'react';
import {Grid, GridItem, PageSection, PageSectionVariants} from '@patternfly/react-core';

import {AppData, Report, ReportMap, isReportMap} from './api/report';
import {SummaryCard} from './components/SummaryCard';
import {ReportErrorAlert} from './components/ReportErrorAlert';

import {MOCK_REPORT} from './mocks/report.mock';
import {TabbedLayout} from "./components/TabbedLayout";
import {DockerTabbedLayout } from './components/DockerTabbedLayout'

const data: AppData =
  process.env.NODE_ENV === 'production' ? ((window as any)['appData'] as AppData) : MOCK_REPORT.basic;

export const AppContext = createContext<AppData>(data);
export const useAppContext = (): AppData => useContext(AppContext);

function App() {
  return (
    <AppContext.Provider value={data}>
      {isReportMap(data.report) ? (
        <PageSection variant={PageSectionVariants.default}>
          <DockerTabbedLayout report={data.report as ReportMap}/>
        </PageSection>
      ) : (
        <>
          <ReportErrorAlert report={data.report as Report}/>
          <PageSection variant={PageSectionVariants.light}>
            <Grid hasGutter>
              <GridItem>
                <SummaryCard report={data.report as Report}/>
              </GridItem>
            </Grid>
          </PageSection>
          <PageSection variant={PageSectionVariants.default}>
            <TabbedLayout report={data.report as Report}/>
          </PageSection>
        </>
      )}
    </AppContext.Provider>
  );
}

export default App;
