import {Card, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm} from '@patternfly/react-core';
import {LicenseInfo} from '../api/report';
import { getCategoryLabel } from '../constants/licenseCategories';

export const ConcludedLicenseDetail = ({concluded}: {concluded: LicenseInfo}) => {
  return (
    <Card style={{backgroundColor: 'var(--pf-v5-global--BackgroundColor--100)'}}>
      <DescriptionList>
        <DescriptionListGroup>
          <DescriptionListTerm>License name</DescriptionListTerm>
          <DescriptionListDescription>{concluded.name || '—'}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Expression</DescriptionListTerm>
          <DescriptionListDescription>{concluded.expression || '—'}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Category</DescriptionListTerm>
          <DescriptionListDescription>
            {concluded.category ? getCategoryLabel(concluded.category) : '—'}
          </DescriptionListDescription>
        </DescriptionListGroup>
      </DescriptionList>
    </Card>
  );
};
