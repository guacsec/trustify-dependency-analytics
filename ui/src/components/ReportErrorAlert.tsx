import React from 'react';
import {Alert, AlertVariant} from '@patternfly/react-core';
import {hasSignUpTab, uppercaseFirstLetter} from '../utils/utils';
import {ProviderStatus, Report} from '../api/report';

export const ReportErrorAlert = ({report}: { report: Report }) => {

  const errorReports = Object.keys(report.providers)
    .map(name => {
      return report.providers[name].status;
    })
    .filter(e => (!e.ok || Object.keys(e.warnings).length > 0) && !hasSignUpTab(e));
  
  const getMessage = (e: ProviderStatus) => {
    let message = e.message;
    if(e.ok && Object.keys(e.warnings).length > 0) {
      return `${uppercaseFirstLetter(e.name)}: ${Object.keys(e.warnings).length} package(s) could not be analyzed`;
    }

    return `${uppercaseFirstLetter(e.name)}: ${message}`;
  }

  return (
    <>
      {errorReports.map((e, index) => {
        return <Alert
          key={index}
          variant={
            e.code >= 500 ? AlertVariant.danger : e.code >= 400 ? AlertVariant.warning : undefined
          }
          title={getMessage(e)}
        />
      })}
    </>
  );
};
