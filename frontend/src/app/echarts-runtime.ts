import { init, use } from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { DataZoomComponent, GridComponent, TooltipComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';

use([BarChart,GridComponent,TooltipComponent,DataZoomComponent,SVGRenderer]);
export function createChart(element:HTMLElement){return init(element,undefined,{renderer:'svg'});}
