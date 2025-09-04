import React from 'react';
import {Alert, AlertVariant} from '@patternfly/react-core';
import {hasSignUpTab, uppercaseFirstLetter} from '../utils/utils';
import {Report} from '../api/report';

export const ReportErrorAlert = ({report}: { report: Report }) => {

  const errorReports = Object.keys(report.providers)
    .map(name => {
      return report.providers[name].status;
    })
    .filter(e => !e.ok && !hasSignUpTab(e));

  return (
    <>
      {errorReports.map((e, index) => {
        if(e.name === 'trusted-content') {
          return <Alert
          key={index}
          variant={
            AlertVariant.info
          }
          title={`${uppercaseFirstLetter(e.name)}: Recommendations and remediations are not currently available`}
        />

        }
        return <Alert
          key={index}
          variant={
            e.code >= 500 ? AlertVariant.danger : e.code >= 400 ? AlertVariant.warning : undefined
          }
          title={`${uppercaseFirstLetter(e.name)}: ${e.message}`}
        />
      })}
    </>
  );
};
