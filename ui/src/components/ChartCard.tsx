import {Bullseye, CardBody} from '@patternfly/react-core';
import {ChartDonut} from '@patternfly/react-charts';
import {Summary} from '../api/report';

const customColors = ['#800000', '#FF0000', '#FFA500', '#5BA352'];

export const ChartCard = ({summary}: { summary: Summary }) => {

  const critical = summary?.critical ?? 0;
  const high = summary?.high ?? 0;
  const medium = summary?.medium ?? 0;
  const low = summary?.low ?? 0;
  const total = summary?.total ?? 0;

  const hasValues = critical + high + medium + low > 0;
  const zeroColor = '#D5F5E3';
  const colorScale = hasValues ? customColors : [zeroColor];

  const legendData = [
    {name: `Critical: ${critical}`, symbol: {type: 'square', fill: customColors[0]}},
    {name: `High: ${high}`, symbol: {type: 'square', fill: customColors[1]}},
    {name: `Medium: ${medium}`, symbol: {type: 'square', fill: customColors[2]}},
    {name: `Low: ${low}`, symbol: {type: 'square', fill: customColors[3]}},
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
                {x: 'Critical', y: critical},
                {x: 'High', y: high},
                {x: 'Medium', y: medium},
                {x: 'Low', y: low},
              ] : [{x: 'Empty', y: 1e-10}]}
              labels={({datum}) => hasValues ? `${datum.x}: ${datum.y}` : 'No vulnerabilities'}
              legendData={legendData}
              legendOrientation="vertical"
              legendPosition="right"
              padding={{
                left: 20,
                right: 140, // Adjusted to accommodate legend
              }}
              subTitle="Unique vulnerabilities"
              title={`${total}`}
              width={350}
              colorScale={colorScale}
            />
          </div>
        </Bullseye>
      </CardBody>
    </div>
  );
};
