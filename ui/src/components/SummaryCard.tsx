import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  Grid,
  GridItem,
  GridItemProps,
  Icon,
  Label,
  LabelGroup,
  List,
  ListItem,
  Title,
  TitleSizes,
} from '@patternfly/react-core';
import ExclamationTriangleIcon from '@patternfly/react-icons/dist/esm/icons/exclamation-triangle-icon';
import { ChartCard } from './ChartCard';
import { getSourceName, getSources, Report, BrandingConfig, LicenseReport, LicensePackageReport } from '../api/report';
import SecurityCheckIcon from '../images/security-check.svg';
import TrustifyIcon from '../images/trustify.png';
import { constructImageName, imageRecommendationLink } from '../utils/utils';
import { useAppContext } from '../App';
import { LicensesChartCard } from './LicensesChartCard';
import { WARNING_SHIELD_COLOR, getCategoryLabelColor, getCategoryRank } from '../constants/licenseCategories';
import SecurityIcon from '@patternfly/react-icons/dist/esm/icons/security-icon';

const ICON_STYLE = { width: '16px', height: '16px', verticalAlign: 'middle' } as const;

/** Min width per chart block so legend doesn't collide with next item (~350px chart + legend). */
const CHART_GROUP_MIN_WIDTH = '330px';

/** Count of licenses in summary that are more restrictive than the given project category. */
function countMoreRestrictiveThan(packages: { [key: string]: LicensePackageReport }, projectCategory: string): number {
  let count = 0;
  const projectRank = getCategoryRank(projectCategory);
  for (const p of Object.values(packages)) {
    const packageRank = getCategoryRank(p.concluded.category);
    if (packageRank < projectRank) {
      count++;
    }
  }
  return count;
 
}

export const SummaryCard = ({ report, isReportMap, purl }: { report: Report; isReportMap?: boolean; purl?: string }) => {
  const appContext = useAppContext();

  // Get branding config from appData with fallback defaults
  const brandingConfig: BrandingConfig = appContext.brandingConfig || {
    displayName: 'Trustify',
    exploreUrl: 'https://guac.sh/trustify/',
    exploreTitle: 'Learn more about Trustify',
    exploreDescription: 'The Trustify project is a collection of software components that enables you to store and retrieve Software Bill of Materials (SBOMs), and advisory documents.',
    imageRecommendation: '',
    imageRecommendationLink: ''
  };

  const showExploreCard = Boolean(brandingConfig.exploreTitle.trim().length > 0) && Boolean(brandingConfig.exploreUrl.trim().length > 0) && Boolean(brandingConfig.exploreDescription.trim().length > 0);
  const showContainerRecommendationsCard = Boolean(isReportMap) && brandingConfig.imageRecommendation.trim().length > 0 && brandingConfig.imageRecommendationLink.trim().length > 0;
  const licensesReports = report.licenses || [];
  const sbomLicenseReport = report.licenses?.find((l: LicenseReport) => l.status.name === 'SBOM');
  const projectLicense = sbomLicenseReport?.projectLicense;
  const showProjectLicenseCard = Boolean(projectLicense);

  const getBrandIcon = () => {
    // Always use the default icon - custom icons can be overridden via CSS
    return <img src={TrustifyIcon} alt="Trustify Icon" style={ICON_STYLE}/>;
  };

  // First row: Vendor Issues + License Summary. Stack until lg (1024px), then side-by-side.
  const firstRowCount = 1 + (licensesReports.length > 0 ? 1 : 0);
  const firstRowSpan = Math.min(12, Math.max(1, Math.floor(12 / firstRowCount))) as GridItemProps['md'];
  const firstRowSpanLg = firstRowSpan as GridItemProps['lg'];
  
  // Second row: Remediations, Project License (if defined), Container recommendations, Explore
  let secondRowCount = 1 + Number(showProjectLicenseCard) + Number(showContainerRecommendationsCard) + Number(showExploreCard);
  
  if(secondRowCount === 4) {
    secondRowCount = 2;
  }
  const secondRowSpan = Math.min(12, Math.max(1, Math.floor(12 / secondRowCount))) as GridItemProps['md'];

  return (
    <Grid hasGutter>
      <Title headingLevel="h3" size={TitleSizes['2xl']} style={{paddingLeft: '15px'}}>
        <Icon isInline status="info">
          <ExclamationTriangleIcon style={{fill: "#f0ab00"}}/>
        </Icon>&nbsp;{brandingConfig.displayName} overview of security issues
      </Title>
      <Divider/>
      {/* Row 1: Vendor Issues and Licenses — full width below lg so they stack */}
      <GridItem md={12} lg={firstRowSpanLg}>
        <Card isFlat isFullHeight>
          <CardHeader>
            <CardTitle>
              <DescriptionListTerm style={{fontSize: "large"}}>
                {isReportMap ? (<>{purl ? constructImageName(purl) : "No Image name"} - Vendor Issues</>
                ) : (
                  <>Vendor Issues</>
                )}
              </DescriptionListTerm>
            </CardTitle>
          </CardHeader>
          <CardBody>
            <DescriptionListGroup>
              <DescriptionListDescription>
                <DescriptionListTerm>
                  Below is a list of dependencies affected with CVE.
                </DescriptionListTerm>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionList
              isAutoFit
              style={{
                paddingTop: '10px',
                gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${CHART_GROUP_MIN_WIDTH}), 1fr))`,
              }}
            >
              {getSources(report).map((source, index) => (
                <DescriptionListGroup
                  key={index}
                  style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 0 }}
                >
                  <DescriptionListTerm style={{ fontSize: 'large' }}>
                    {getSourceName(source)}
                  </DescriptionListTerm>
                  <DescriptionListDescription>
                    <ChartCard summary={source.report.summary} />
                  </DescriptionListDescription>
                </DescriptionListGroup>
              ))}
            </DescriptionList>
          </CardBody>
          <Divider/>
        </Card>
      </GridItem>
      {licensesReports.length > 0 && (
        <GridItem md={12} lg={firstRowSpanLg}>
          <Card isFlat isFullHeight>
            <CardHeader>
              <CardTitle>
                <DescriptionListTerm style={{fontSize: "large"}}>
                  License Summary
                </DescriptionListTerm>
              </CardTitle>
            </CardHeader>
            <CardBody>
              <DescriptionList
                isAutoFit
                style={{
                  paddingTop: '30px',
                  gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${CHART_GROUP_MIN_WIDTH}), 1fr))`,
                }}
              >
                {licensesReports.map((licenseReport, index) => (
                  <DescriptionListGroup
                    key={index}
                    style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 0 }}
                  >
                    <DescriptionListTerm style={{ fontSize: 'large' }}>
                      {licenseReport.status.name || 'Unknown'}
                    </DescriptionListTerm>
                    <DescriptionListDescription>
                      <LicensesChartCard summary={licenseReport.summary} />
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                ))}
              </DescriptionList>
            </CardBody>
          </Card>
        </GridItem>
      )}
      {/* Row 2: Remediations, Container recommendations, Explore */}
      <GridItem md={secondRowSpan}>
        <Card isFlat isFullHeight>
          <DescriptionListGroup>
            <CardTitle component="h4">
              <DescriptionListTerm style={{fontSize: "large"}}>
                {getBrandIcon()}&nbsp;
                {brandingConfig.displayName} Dependency Remediations
              </DescriptionListTerm>
            </CardTitle>
            <CardBody>
              <DescriptionListDescription>
                  <List isPlain>
                    {getSources(report).map((source, index) => {
                      let remediationsSrc =
                      source && source.source && source.provider
                        ? source.source === source.provider
                          ? source.provider
                          : `${source.provider}/${source.source}`
                        : "default_value"; // Provide a fallback value
                      if (Object.keys(source.report).length > 0) {
                        return (
                          <ListItem>
                            <Icon isInline status="success">
                              <img src={SecurityCheckIcon} alt="Security Check Icon"/>
                            </Icon>&nbsp;{source.report.summary.remediations} remediations are available
                            for {remediationsSrc}
                          </ListItem>
                        )
                      }
                      return (
                        <ListItem>
                          <Icon isInline status="success">
                            <img src={SecurityCheckIcon} alt="Security Check Icon"/>
                          </Icon>&nbsp;
                          There are no available remediations for your SBOM at this time for {source.provider}
                        </ListItem>
                      )
                    })
                    }
                  </List>
              </DescriptionListDescription>
            </CardBody>
          </DescriptionListGroup>
        </Card>&nbsp;
      </GridItem>
      {showProjectLicenseCard && projectLicense && (
        <GridItem md={secondRowSpan}>
          <Card isFlat isFullHeight>
            <DescriptionListGroup>
              <CardTitle component="h4">
                <DescriptionListTerm style={{ fontSize: 'large' }}>
                  Project License  <LabelGroup>
                      <Label color={getCategoryLabelColor(projectLicense.category)}>{projectLicense.expression || projectLicense.name || '—'}</Label>
                    </LabelGroup>
                </DescriptionListTerm>
              </CardTitle>
              <CardBody>
                <DescriptionListDescription>
                  <DescriptionListGroup>
                    <DescriptionListTerm>License incompatibilities</DescriptionListTerm>
                  </DescriptionListGroup>
                  <List isPlain>
                    {licensesReports.map((licenseReport: LicenseReport, index: number) => {
                      const count = countMoreRestrictiveThan(licenseReport.packages, projectLicense.category);
                      const providerName = licenseReport.status.name || 'Unknown';
                      return (
                        <ListItem key={index}>
                          {count === 0 ? (
                            <>
                              <Icon isInline status="success">
                              <img src={SecurityCheckIcon} alt="Security Check Icon"/>
                              </Icon>
                              &nbsp;0 license incompatibilities found for {providerName}
                            </>
                          ) : (
                            <>
                              <Icon isInline status="warning">
                              <SecurityIcon  style={{fill: WARNING_SHIELD_COLOR, height: '13px'}}/>
                              </Icon>
                              &nbsp;{count} dependenc{count === 1 ? 'y' : 'ies'} have more restrictive licenses for {providerName}
                            </>
                          )}
                        </ListItem>
                      );
                    })}
                  </List>
                </DescriptionListDescription>
              </CardBody>
            </DescriptionListGroup>
          </Card>&nbsp;
        </GridItem>
      )}
      {showContainerRecommendationsCard && (
        <GridItem md={secondRowSpan}>
          <Card isFlat isFullHeight>
            <DescriptionListGroup>
              <CardTitle component="h4">
                <DescriptionListTerm style={{fontSize: "large"}}>
                  {getBrandIcon()}&nbsp;
                  {brandingConfig.displayName} Container Recommendations
                </DescriptionListTerm>
              </CardTitle>
              <CardBody>
                <DescriptionListDescription>
                    <List isPlain>
                      <ListItem>
                        {brandingConfig.imageRecommendation}
                      </ListItem>
                      <ListItem>
                        <a href={purl ? imageRecommendationLink(purl, report, appContext.imageMapping, brandingConfig.imageRecommendationLink) : '###'}
                            target="_blank" rel="noreferrer">
                          <Button variant="primary" size="sm">
                            Take me there
                          </Button>
                        </a>
                      </ListItem>
                    </List>
                </DescriptionListDescription>
              </CardBody>
            </DescriptionListGroup>
          </Card>&nbsp;
        </GridItem>
      )}
      {showExploreCard && (
        <GridItem md={secondRowSpan}>
        <Card isFlat isFullHeight>
          <DescriptionListGroup>
            <CardTitle component="h4">
              <DescriptionListTerm style={{fontSize: "large"}}>
{brandingConfig.exploreTitle}
              </DescriptionListTerm>
            </CardTitle>
            <CardBody>
              <DescriptionListDescription>
                <List isPlain>
                  <ListItem>
{brandingConfig.exploreDescription}
                  </ListItem>
                  <ListItem>
                    <a href={brandingConfig.exploreUrl} target="_blank"
                       rel="noopener noreferrer">
                      <Button variant="primary" size="sm">
                        Take me there
                      </Button>
                    </a>
                  </ListItem>
                </List>
              </DescriptionListDescription>
            </CardBody>
          </DescriptionListGroup>
        </Card>&nbsp;
      </GridItem>
      )}
    </Grid>
  );
};
