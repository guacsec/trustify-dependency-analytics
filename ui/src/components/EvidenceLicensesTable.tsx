import {useMemo} from 'react';
import {Card, Flex, FlexItem, Icon} from '@patternfly/react-core';
import {Table, TableVariant, Tbody, Td, Th, Thead, Tr} from '@patternfly/react-table';
import SecurityIcon from '@patternfly/react-icons/dist/esm/icons/security-icon';
import {LicenseInfo} from '../api/report';
import { getCategoryColor, getCategoryLabel, getCategorySortIndex, WARNING_SHIELD_COLOR } from '../constants/licenseCategories';
import {ConditionalTableBody} from './TableControls/ConditionalTableBody';

const FSF_LOGO_URL = 'https://www.gnu.org/graphics/fsf-logo-notext-small.png';
const OSI_LOGO_URL = 'https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/open-source-initiative.svg';

const columnNames = {
  evidence: 'Evidence',
  expression: 'Expression',
  identifiers: 'Identifiers',
  category: 'Category',
  status: 'Status',
};

function IdentifierBadges({info}: {info: LicenseInfo}) {
  const ids = info?.identifiers ?? [];
  const isDeprecated = ids.some((i) => i.isDeprecated === true);
  const isOsiApproved = ids.some((i) => i.isOsiApproved === true);
  const isFsfLibre = ids.some((i) => i.isFsfLibre === true);
  if (!isDeprecated && !isOsiApproved && !isFsfLibre) return <>—</>;
  return (
    <Flex gap={{default: 'gapSm'}} alignItems={{default: 'alignItemsCenter'}}>
      {isDeprecated && (
        <FlexItem>
          <span title="Deprecated identifier">
            <Icon isInline>
              <SecurityIcon style={{ fill: WARNING_SHIELD_COLOR, height: '13px' }} />
            </Icon>
          </span>
        </FlexItem>
      )}
      {isOsiApproved && (
        <FlexItem>
          <img
            src={OSI_LOGO_URL}
            alt="OSI Approved"
            title="OSI Approved"
            style={{height: '1.1em', verticalAlign: 'middle'}}
          />
        </FlexItem>
      )}
      {isFsfLibre && (
        <FlexItem>
          <img
            src={FSF_LOGO_URL}
            alt="FSF Libre"
            title="FSF Free/Libre"
            style={{height: '1.1em', verticalAlign: 'middle'}}
          />
        </FlexItem>
      )}
    </Flex>
  );
}

export const EvidenceLicensesTable = ({
  evidence = [],
}: {
  evidence: LicenseInfo[];
}) => {
  const sortedEvidence = useMemo(
    () => [...evidence].sort((a, b) => getCategorySortIndex(a.category) - getCategorySortIndex(b.category)),
    [evidence]
  );

  return (
    <Card
      style={{
        backgroundColor: 'var(--pf-v5-global--BackgroundColor--100)',
      }}
    >
      <Table variant={TableVariant.compact} aria-label="Evidence licenses">
        <Thead>
          <Tr>
            <Th width={30}>{columnNames.evidence}</Th>
            <Th width={20}>{columnNames.expression}</Th>
            <Th width={25}>{columnNames.identifiers}</Th>
            <Th width={15}>{columnNames.category}</Th>
            <Th width={10}>{columnNames.status}</Th>
          </Tr>
        </Thead>
        <ConditionalTableBody isNoData={sortedEvidence.length === 0} numRenderedColumns={5}>
          <Tbody>
            {sortedEvidence.map((info, rowIndex) => {
              const evidenceLabel = info.name || info.identifiers?.map((i) => i.name || i.id).join(', ') || info.expression || '—';
              const expression = info.expression || '—';
              const identifierIds = info.identifiers?.map((i) => i.id) ?? [];
              const category = info.category || '—';
              const color = getCategoryColor(info.category);
              return (
                <Tr key={rowIndex}>
                  <Td dataLabel={columnNames.evidence}>{evidenceLabel}</Td>
                  <Td dataLabel={columnNames.expression}>{expression}</Td>
                  <Td dataLabel={columnNames.identifiers} style={{ whiteSpace: 'pre-line' }}>
                    {identifierIds.length ? identifierIds.join('\n') : '—'}
                  </Td>
                  <Td dataLabel={columnNames.category}>
                    {category !== '—' ? (
                      <span>
                        <Icon isInline>
                          <SecurityIcon style={{fill: color, height: '13px'}} />
                        </Icon>
                        &nbsp;
                        {getCategoryLabel(info.category)}
                      </span>
                    ) : (
                      '—'
                    )}
                  </Td>
                  <Td dataLabel={columnNames.status}>
                    <IdentifierBadges info={info} />
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </ConditionalTableBody>
      </Table>
    </Card>
  );
};
