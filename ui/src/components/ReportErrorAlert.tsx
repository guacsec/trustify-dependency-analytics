import React from 'react';
import {Alert, AlertVariant} from '@patternfly/react-core';
import {hasSignUpTab, uppercaseFirstLetter} from '../utils/utils';
import {ProviderStatus, Report} from '../api/report';

export const ReportErrorAlert = ({report}: { report: Report }) => {
  
  const isWarning = (e: ProviderStatus) => {
    return e.code >= 400 || Object.keys(e.warnings).length > 0;
  }

  const errorReports = Object.keys(report.providers)
    .map(name => {
      return report.providers[name].status;
    })
    .filter(e => (!e.ok || isWarning(e)) && !hasSignUpTab(e));

  const getVariant = (e: ProviderStatus) => {
    if(e.ok && !isWarning(e)) {
      return AlertVariant.info;
    }
    return e.code >= 500 ? AlertVariant.danger : AlertVariant.warning;
  }

  const getMessage = (e: ProviderStatus) => {
    let message = e.message;
    if(e.ok && isWarning(e)) {
      return `${uppercaseFirstLetter(e.name)}: ${Object.keys(e.warnings).length} package(s) could not be analyzed`;
    }

    return `${uppercaseFirstLetter(e.name)}: ${message}`;
  }

  return (
    <>
      {errorReports.map((e, index) => {
        return <Alert
          key={index}
          variant={getVariant(e)}
          title={getMessage(e)}
        />
      })}
    </>
  );
};
