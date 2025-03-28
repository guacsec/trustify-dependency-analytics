import {Table, TableVariant, Tbody, Th, Thead, Tr} from '@patternfly/react-table';
import {buildVulnerabilityItems, TransitiveDependency} from '../api/report';
import {ConditionalTableBody} from './TableControls/ConditionalTableBody';
import {Card,} from '@patternfly/react-core';
import {VulnerabilityRow} from "./VulnerabilityRow";

export const TransitiveDependenciesTable = ({
                                              providerName,
                                              transitiveDependencies
                                            }: { providerName: string; transitiveDependencies: TransitiveDependency[] }) => {
  return (
    <Card
      style={{
        backgroundColor: 'var(--pf-v5-global--BackgroundColor--100)',
      }}
    >
      <Table variant={TableVariant.compact} aria-label={(providerName ?? "Default") + " transitive vulnerabilities"}>
        <Thead>
          <Tr>
            <Th width={15}>Vulnerability ID</Th>
            <Th width={20}>Description</Th>
            <Th width={10}>Severity</Th>
            <Th width={15}>CVSS Score</Th>
            <Th width={20}>Transitive Dependency</Th>
            <Th width={20}>Remediation</Th>
          </Tr>
        </Thead>
        <ConditionalTableBody isNoData={transitiveDependencies.length === 0} numRenderedColumns={7}>
          {buildVulnerabilityItems(transitiveDependencies).map((item, rowIndex) => (
            <Tbody key={rowIndex}>
              <VulnerabilityRow item={item} providerName={providerName} rowIndex={rowIndex} />
            </Tbody>
          ))}
        </ConditionalTableBody>
      </Table>
    </Card>
  );
};
