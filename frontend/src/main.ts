import "uplot/dist/uPlot.min.css";
import {
  CompleteReport,
  completeReportToSeries,
  fetchReportByName,
  fetchReportNames,
} from "./data";
import { buildPlot } from "./plot";
import "./style.css";

(async () => {
  const stackTraceArea = document.getElementById("stacktraceArea")!;

  stackTraceArea.textContent = "Fetching report names..."
  const reportNames = await fetchReportNames();

  stackTraceArea.textContent += `\nFetching ${reportNames.length} reports`
  const reports = await Promise.all(reportNames.map(fetchReportByName));

  stackTraceArea.textContent += "\n\nBuilding Graph series"
  const uplotData = completeReportToSeries(reports as CompleteReport);

  stackTraceArea.textContent += "\n\nDisplaying plot"
  buildPlot(uplotData);
})();
