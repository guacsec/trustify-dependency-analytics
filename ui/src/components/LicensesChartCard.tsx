import { Bullseye, CardBody } from '@patternfly/react-core';
import { ChartDonut } from '@patternfly/react-charts';
import { LicenseSummary } from '../api/report';
import { CATEGORY_COLORS } from '../constants/licenseCategories';

export const LicensesChartCard = ({summary}: { summary: LicenseSummary }) => {

  const permissive = summary["permissive"] ?? 0;
  const strongCopyleft = summary["strongCopyleft"] ?? 0;
  const unknown = summary["unknown"] ?? 0;
  const weakCopyleft = summary["weakCopyleft"] ?? 0;
  const total = summary["total"] ?? 0;

  const hasValues = permissive + strongCopyleft + unknown + weakCopyleft > 0;

  const legendData = [
    {name: `Permissive: ${permissive}`, symbol: {type: 'square', fill: CATEGORY_COLORS.PERMISSIVE}},
    {name: `Weak Copyleft: ${weakCopyleft}`, symbol: {type: 'square', fill: CATEGORY_COLORS.WEAK_COPYLEFT}},
    {name: `Strong Copyleft: ${strongCopyleft}`, symbol: {type: 'square', fill: CATEGORY_COLORS.STRONG_COPYLEFT}},
    {name: `Unknown: ${unknown}`, symbol: {type: 'square', fill: CATEGORY_COLORS.UNKNOWN}},
  ];

  return (
    <div>
      {/* Chart */}
      <CardBody style={{paddingBottom: "inherit", padding: "0"}}>
        <Bullseye>
          <div style={{height: '230px', width: '350px'}}>
            <ChartDonut
              constrainToVisibleArea
              data={hasValues ? [
                {x: 'Permissive', y: permissive},
                {x: 'Weak Copyleft', y: weakCopyleft},
                {x: 'Strong Copyleft', y: strongCopyleft},
                {x: 'Unknown', y: unknown},
              ] : [{x: 'Empty', y: 1e-10}]}
              labels={({datum}) => hasValues ? `${datum.x}: ${datum.y}` : 'No licenses'}
              legendData={legendData}
              legendOrientation="vertical"
              legendPosition="right"
              padding={{
                left: 0,
                right: 160, // Adjusted to accommodate legend
              }}
              subTitle="Total licenses"
              title={`${total}`}
              width={350}
              colorScale={Object.values(CATEGORY_COLORS)}
            />
          </div>
        </Bullseye>
      </CardBody>
    </div>
  );
};
