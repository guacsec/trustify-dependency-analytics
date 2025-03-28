import {Table, TableVariant, Tbody, Th, Thead, Tr} from '@patternfly/react-table';
import {Dependency, Vulnerability} from '../api/report';
import {ConditionalTableBody} from './TableControls/ConditionalTableBody';
import {Card} from '@patternfly/react-core';
import {VulnerabilityRow} from "./VulnerabilityRow";

export const VulnerabilitiesTable = ({ providerName, dependency, vulnerabilities }: { providerName: string; dependency: Dependency; vulnerabilities: Vulnerability[] }) => {
  return (
    <Card
      style={{
        backgroundColor: 'var(--pf-v5-global--BackgroundColor--100)',
      }}
    >
      <Table variant={TableVariant.compact} aria-label={(providerName ?? "Default") + " direct vulnerabilities"}>
        <Thead>
          <Tr>
            <Th width={15}>Vulnerability ID</Th>
            <Th width={20}>Description</Th>
            <Th width={10}>Severity</Th>
            <Th width={15}>CVSS Score</Th>
            <Th width={20}>Direct Dependency</Th>
            <Th width={20}>Remediation</Th>
          </Tr>
        </Thead>
        <ConditionalTableBody isNoData={vulnerabilities.length === 0} numRenderedColumns={6}>
          {vulnerabilities?.map((vuln, rowIndex) => {
            let ids = [];
            if(vuln.cves && vuln.cves.length > 0) {
              vuln.cves.forEach(cve => ids.push(cve));
            } else if(vuln.unique) {
              ids.push(vuln.id);
            }
            return (
              <Tbody key={rowIndex}>
                {ids.map((_, index) => (
                  <VulnerabilityRow key={`${rowIndex}-${index}`}
                    item={{
                      id: vuln.id,
                      dependencyRef: dependency.ref,
                      vulnerability: vuln,
                    }}
                    providerName={providerName}
                    rowIndex={rowIndex}
                  />
                ))}
              </Tbody>
            );
          })}
        </ConditionalTableBody>
      </Table>
    </Card>
  );
};