import uPlot from "uplot";
import { PlotData, ProcessReport } from "./data";
import { binarySearch } from "./util";
import { generateColors } from "./colors";

function displayStackframePlugin(plotData: PlotData): uPlot.Plugin {
  let dataIdx: null | number = null;
  let seriesIdx: null | number = null;

  function updateDisplay() {
    const traceArea = document.getElementById("stacktraceArea")!;

    if (dataIdx === null || seriesIdx === null) {
      traceArea.replaceChildren();
      return;
    }
    // -1 for x?
    const reportIndex = Math.floor((seriesIdx - 1) / 2);
    const report = plotData.reports[reportIndex];

    const index = binarySearch(
      report.entries,
      plotData.xData[dataIdx],
      (it) => it.time
    );
    if (index < 0) {
      // This process has no sample at the hovered time
      traceArea.replaceChildren();
      return;
    }
    const entry = report.entries[index];
    traceArea.replaceChildren();

    if (entry.stacktrace_error) {
      const error = document.createElement("p");
      error.textContent = `Capturing stacktraces failed: ${entry.stacktrace_error}`;
      traceArea.append(error);
    }

    // Sort them by ID to have the main thread appear first
    const threads = entry.stacktraces.slice();
    threads.sort((a, b) => b.thread_id - a.thread_id);

    for (const thread of threads) {
      const heading = document.createElement("h3");
      heading.textContent = `${thread.os_thread_id ?? thread.thread_id} (${thread.thread_name})`;

      const frames = document.createElement("div");
      frames.className = "frames";
      frames.textContent = thread.frames
        .map((frame) => `${frame.name} (${frame.short_filename}:${frame.line})\n`)
        .join("");

      traceArea.append(heading, frames);
    }
  }

  return {
    hooks: {
      setCursor: (u) => {
        const idx = u.cursor.idx;
        if (idx !== dataIdx) {
          dataIdx = idx ?? null;
          updateDisplay();
        }
      },
      setSeries(_, idx) {
        if (seriesIdx !== idx) {
          seriesIdx = idx;
          updateDisplay();
        }
      },
    },
  };
}

function buildMemorySeries(report: ProcessReport, color: string): uPlot.Series {
  return {
    show: true,

    spanGaps: false,
    scale: "byte",

    // in-legend display
    label: `RAM (${report.id})`,
    value: (_, rawValue) =>
      rawValue === null ? "--" : (rawValue / 1024 / 1024).toFixed(1) + "MiB",

    // series style
    stroke: color,
    width: 1,
  };
}

function buildCpuSeries(report: ProcessReport, color: string): uPlot.Series {
  return {
    show: true,

    spanGaps: false,
    scale: "%",

    // in-legend display
    label: `CPU (${report.id})`,
    value: (_, rawValue) =>
      rawValue === null ? "--" : rawValue.toFixed(0) + "%",

    // series style
    stroke: color,
    width: 1,
    dash: [5],
  };
}

function buildPlotOptions(plotData: PlotData, colors: string[]): uPlot.Options {
  const options: uPlot.Options = {
    title: "Resource Usage",
    id: "chart1",
    class: "my-chart",
    width: 800,
    height: 600,
    series: [{}],
    legend: {
      live: true,
    },
    scales: {
      byte: {
        distr: 1,
      },
    },
    axes: [
      {},
      {
        size: 80,
        scale: "byte",
        values: (_, ticks) =>
          ticks.map(
            (rawValue) => (rawValue / 1024 / 1024 / 1024).toFixed(1) + "GiB"
          ),
      },
      {
        scale: "%",
        values: (_, ticks) =>
          ticks.map((rawValue) => rawValue.toFixed(0) + "%"),
        side: 1,
        grid: { show: false },
      },
    ],
    cursor: {
      focus: {
        prox: 5,
      },
      lock: true,
    },
    plugins: [displayStackframePlugin(plotData)],
  };

  let counter = 0;
  for (const report of plotData.reports) {
    options.series.push(buildCpuSeries(report, colors[counter]));
    options.series.push(buildMemorySeries(report, colors[counter]));

    counter += 1;
  }

  for (const series of options.series) {
    if (isGlobalSeries(series)) {
      series.show = false;
    }
  }

  return options;
}

function seriesLabel(series: uPlot.Series): string | undefined {
  return series.label instanceof HTMLElement ? series.label.textContent : series.label;
}

function isGlobalSeries(series: uPlot.Series): boolean {
  return !!seriesLabel(series)?.includes("global.json")
}

export function buildPlot(plotData: PlotData): uPlot {
  const colors = generateColors(plotData.yData.length);
  const plot = new uPlot(
    buildPlotOptions(plotData, colors),
    [plotData.xData.map((it) => it / 1000), ...plotData.yData],
    document.getElementById("chartContainer")!
  );

  const observer = new ResizeObserver(() => {
    const container = document.getElementById("chartContainer")!;
    plot.setSize(container.getBoundingClientRect());
  });
  observer.observe(document.getElementById("chartContainer")!);

  document.getElementById("plotOptionToggleAll")!.onclick = () => {
    const allShown = plot.series.filter(it => !isGlobalSeries(it)).every((it) => it.show);

    let newState = allShown ? false : true;
    for (let i = 0; i < plot.series.length; i++) {
      plot.setSeries(i, { show: newState && !isGlobalSeries(plot.series[i]) });
    }
  };

  document.getElementById("plotOptionsOnlyMem")!.onclick = () => {
    for (let i = 0; i < plot.series.length; i++) {
      const series = plot.series[i];
      plot.setSeries(i, { show: seriesLabel(series)?.includes("RAM") && !isGlobalSeries(series) });
    }
  };
  document.getElementById("plotOptionsOnlyCpu")!.onclick = () => {
    for (let i = 0; i < plot.series.length; i++) {
      const series = plot.series[i];
      plot.setSeries(i, { show: seriesLabel(series)?.includes("CPU") && !isGlobalSeries(series) });
    }
  };

  return plot;
}
