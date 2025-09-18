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
import {getSourceName, getSources, Report} from '../api/report';
import RedhatIcon from "@patternfly/react-icons/dist/esm/icons/redhat-icon";
import SecurityCheckIcon from '../images/security-check.svg';
import {constructImageName, imageRemediationLink} from '../utils/utils';
import {useAppContext} from "../App";

export const SummaryCard = ({report, isReportMap, purl}: { report: Report, isReportMap?: boolean, purl?: string }) => {
  const appContext = useAppContext();
  const gridItemMd = appContext.rhdaSource !== 'trustification' ? 6 : undefined;

  return (
    <Grid hasGutter>
      <Title headingLevel="h3" size={TitleSizes['2xl']} style={{paddingLeft: '15px'}}>
        <Icon isInline status="info">
          <ExclamationTriangleIcon style={{fill: "#f0ab00"}}/>
        </Icon>&nbsp;Red Hat Overview of security Issues
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
      <GridItem md={gridItemMd}>
        <Card isFlat>
          <DescriptionListGroup>
            <CardTitle component="h4">
              <DescriptionListTerm style={{fontSize: "large"}}>
                <Icon isInline status="info">
                  <RedhatIcon style={{fill: "#cc0000"}}/>
                </Icon>&nbsp;
                Red Hat Remediations
              </DescriptionListTerm>
            </CardTitle>
            <CardBody>
              <DescriptionListDescription>
                {isReportMap ? (
                  <List isPlain>
                    <ListItem>
                      Switch to UBI 9 for enhanced security and enterprise-grade stability in your containerized
                      applications, backed by Red Hat's support and compatibility assurance.
                    </ListItem>
                    <ListItem>
                      <a href={purl ? imageRemediationLink(purl, report, appContext.imageMapping) : '###'}
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
                            </Icon>&nbsp;{source.report.summary.remediations} remediations are available from Red Hat
                            for {remediationsSrc}
                          </ListItem>
                        )
                      }
                      return (
                        <ListItem>
                          <Icon isInline status="success">
                            <img src={SecurityCheckIcon} alt="Security Check Icon"/>
                          </Icon>&nbsp;
                          There are no available Red Hat remediations for your SBOM at this time for {source.provider}
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
      {appContext.rhdaSource !== 'trustification' && (
        <GridItem md={6}>
        <Card isFlat>
          <DescriptionListGroup>
            <CardTitle component="h4">
              <DescriptionListTerm style={{fontSize: "large"}}>
                Join to explore Red Hat TPA
              </DescriptionListTerm>
            </CardTitle>
            <CardBody>
              <DescriptionListDescription>
                <List isPlain>
                  <ListItem>
                    Check out our new Trusted Profile Analyzer to get visibility and insight into your software risk
                    profile, for instance by exploring vulnerabilites or analyzing SBOMs.
                  </ListItem>
                  <ListItem>
                    <a href="https://developers.redhat.com/products/trusted-profile-analyzer/overview" target="_blank"
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