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
  Icon,
  List,
  ListItem,
  Title,
  TitleSizes,
} from '@patternfly/react-core';
import ExclamationTriangleIcon from '@patternfly/react-icons/dist/esm/icons/exclamation-triangle-icon';
import {ChartCard} from './ChartCard';
import {getSourceName, getSources, Report, BrandingConfig} from '../api/report';
import SecurityCheckIcon from '../images/security-check.svg';
import TrustifyIcon from '../images/trustify.png';
import {constructImageName, imageRemediationLink} from '../utils/utils';
import {useAppContext} from "../App";

const hasTrustifyProvider = (obj: any): boolean => {
  return obj && typeof obj === 'object' && 'rhtpa' in obj;
};

const ICON_STYLE = {width: "16px", height: "16px", verticalAlign: "middle"} as const;

export const SummaryCard = ({report, isReportMap, purl}: { report: Report, isReportMap?: boolean, purl?: string }) => {
  const appContext = useAppContext();
  const showTrustifyCard = hasTrustifyProvider(appContext.report.providers);

  // Get branding config from appData with fallback defaults
  const brandingConfig: BrandingConfig = appContext.brandingConfig || {
    displayName: 'Trustify',
    exploreUrl: 'https://guac.sh/trustify/',
    exploreTitle: 'Learn more about Trustify',
    exploreDescription: 'The Trustify project is a collection of software components that enables you to store and retrieve Software Bill of Materials (SBOMs), and advisory documents.',
    imageRecommendation: '',
    imageRemediationLink: ''
  };

  const getBrandIcon = () => {
    // Always use the default icon - custom icons can be overridden via CSS
    return <img src={TrustifyIcon} alt="Trustify Icon" style={ICON_STYLE}/>;
  };


  return (
    <Grid hasGutter>
      <Title headingLevel="h3" size={TitleSizes['2xl']} style={{paddingLeft: '15px'}}>
        <Icon isInline status="info">
          <ExclamationTriangleIcon style={{fill: "#f0ab00"}}/>
        </Icon>&nbsp;{brandingConfig.displayName} Overview of security issues
      </Title>
      <Divider/>
      <GridItem>
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
            <DescriptionList isAutoFit style={{paddingTop: "10px"}}>
              {
                getSources(report).map((source, index) => {
                    return (
                      <DescriptionListGroup key={index}
                                            style={{display: "flex", flexDirection: "column", alignItems: "center"}}>
                        <>
                          <DescriptionListTerm style={{fontSize: "large"}}>
                            {getSourceName(source)}
                          </DescriptionListTerm>
                        </>
                        <DescriptionListDescription>
                          <ChartCard summary={source.report.summary}/>
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                    )
                  }
                )
              }
            </DescriptionList>
          </CardBody>
          <Divider/>
        </Card>
      </GridItem>
      {(!isReportMap || (brandingConfig.imageRecommendation.trim() && brandingConfig.imageRemediationLink.trim())) && (
        <GridItem md={showTrustifyCard ? 6 : undefined}>
          <Card isFlat>
            <DescriptionListGroup>
              <CardTitle component="h4">
                <DescriptionListTerm style={{fontSize: "large"}}>
                  {getBrandIcon()}&nbsp;
                  {brandingConfig.displayName} Remediations
                </DescriptionListTerm>
              </CardTitle>
              <CardBody>
                <DescriptionListDescription>
                  {isReportMap ? (
                    <List isPlain>
                      <ListItem>
                        {brandingConfig.imageRecommendation}
                      </ListItem>
                      <ListItem>
                        <a href={purl ? imageRemediationLink(purl, report, appContext.imageMapping, brandingConfig.imageRemediationLink) : '###'}
                           target="_blank" rel="noreferrer">
                          <Button variant="primary" size="sm">
                            Take me there
                          </Button>
                        </a>
                      </ListItem>
                    </List>
                  ) : (
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
                  )}
                </DescriptionListDescription>
              </CardBody>
            </DescriptionListGroup>
          </Card>&nbsp;
        </GridItem>
      )}
      {showTrustifyCard && (
        <GridItem md={6}>
        <Card isFlat>
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