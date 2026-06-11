import React from 'react';
import {FlexItem, Icon} from '@patternfly/react-core';
import {TransitiveDependency, Vulnerability} from '../api/report';
import SecurityIcon from "@patternfly/react-icons/dist/esm/icons/security-icon";

export const VulnerabilitiesCountBySeverity = ({
                                                   vulnerabilities = [],
                                                   transitiveDependencies = [],
                                               }: {
    vulnerabilities?: Vulnerability[];
    transitiveDependencies?: TransitiveDependency[];
}) => {

    const severityCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        UNKNOWN: 0,
    };
    if (vulnerabilities.length > 0) {
        // Loop through the issues and increment severity counts
        vulnerabilities.forEach((issue) => {
            const severity = issue.severity;
            if (severity && severityCounts.hasOwnProperty(severity)) {
                severityCounts[severity]++;
            }
        });
    } else {
        transitiveDependencies?.forEach((dependency) => {
            dependency.issues?.forEach((issue) => {
                const severity = issue.severity;
                if (severity && severityCounts.hasOwnProperty(severity)) {
                    severityCounts[severity]++;
                }
            });
        });
    }

    return (
        <FlexItem>
            {severityCounts.CRITICAL > 0 && (
                <>
                    <Icon isInline>
                        <SecurityIcon style={{fill: '#800000', height: '13px'}}/>
                    </Icon>&nbsp;
                    {severityCounts.CRITICAL}&nbsp;
                </>
            )}
            {severityCounts.HIGH > 0 && (
                <>
                    <Icon isInline>
                        <SecurityIcon style={{fill: '#FF0000', height: '13px'}}/>
                    </Icon>&nbsp;
                    {severityCounts.HIGH}&nbsp;
                </>
            )}
            {severityCounts.MEDIUM > 0 && (
                <>
                    <Icon isInline>
                        <SecurityIcon style={{fill: '#FFA500', height: '13px'}}/>
                    </Icon>&nbsp;
                    {severityCounts.MEDIUM}&nbsp;
                </>
            )}
            {severityCounts.LOW > 0 && (
                <>
                    <Icon isInline>
                        <SecurityIcon style={{fill: '#5BA352', height: '13px'}}/>
                    </Icon>&nbsp;
                    {severityCounts.LOW}&nbsp;
                </>
            )}
            {severityCounts.UNKNOWN > 0 && (
                <>
                    <Icon isInline>
                        <SecurityIcon style={{fill: '#808080', height: '13px'}}/>
                    </Icon>&nbsp;
                    {severityCounts.UNKNOWN}
                </>
            )}
        </FlexItem>
    );
};
