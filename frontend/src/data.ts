import { z } from "zod";

export const ProcessResourceSchema = z.object({
  memory: z.number(),
  cpu: z.number(),
});
export type ProcessResource = z.infer<typeof ProcessResourceSchema>;

export const StackFrameSchema = z.object({
  name: z.string(),
  filename: z.string(),
  module: z.string().nullable(),
  short_filename: z.string(),
  line: z.number(),
  locals: z.null(), // TODO: What is this
  is_entry: z.boolean(),
});
export type StackFrame = z.infer<typeof StackFrameSchema>;

export const ThreadDumpSchema = z.object({
  pid: z.number(),
  thread_id: z.number(),
  thread_name: z.string().nullable(),
  os_thread_id: z.number(),
  active: z.boolean(),
  owns_gil: z.boolean(),
  frames: z.array(StackFrameSchema),
  process_info: z.null(), // TODO: What is this?
});
export type ThreadDump = z.infer<typeof ThreadDumpSchema>;

export const ProcessReportEntrySchema = z.object({
  stacktraces: z.array(ThreadDumpSchema),
  resources: ProcessResourceSchema,
  index: z.number(),
  time: z.number(),
});
export type ProcessReportEntry = z.infer<typeof ProcessReportEntrySchema>;

export type ProcessId = string;
export type ProcessReport = {
  id: ProcessId;
  entries: ProcessReportEntry[];
};

export type CompleteReport = ProcessReport[];

export type PlotData = {
  reports: ProcessReport[];
  xData: number[];
  yData: (number | null)[][];
};

export function parseJsonProcessReport(
  id: ProcessId,
  reportString: string
): ProcessReport {
  const entries = [];

  for (const line of reportString.split("\n")) {
    if (!line) {
      continue;
    }
    entries.push(ProcessReportEntrySchema.parse(JSON.parse(line)));
  }

  return {
    id,
    entries,
  };
}

export function processReportToSeries(
  report: ProcessReport,
  xAxisTimes: number[]
): { cpuValues: (number | null)[]; memoryValues: (number | null)[] } {
  let memoryValues = [];
  let cpuValues = [];
  let currentTimeIndex = 0;

  // Pad with nulls until our time has come
  while (xAxisTimes[currentTimeIndex] < report.entries[0].time) {
    memoryValues.push(null);
    cpuValues.push(null);
    currentTimeIndex++;
  }
  // Copy over the entries
  for (const entry of report.entries) {
    // If there are any gaps (because sampling failed), we need to fill them with nulls
    while (entry.time < xAxisTimes[currentTimeIndex]) {
      memoryValues.push(null);
      cpuValues.push(null);
      currentTimeIndex++;
    }

    memoryValues.push(entry.resources.memory);
    cpuValues.push(entry.resources.cpu);
  }
  // Fill the rest with nulls
  for (let i = cpuValues.length; i < xAxisTimes.length; i++) {
    cpuValues.push(null);
    memoryValues.push(null);
  }

  return {
    cpuValues,
    memoryValues,
  };
}

export function completeReportToSeries(reports: CompleteReport): PlotData {
  const seriesArray = [];
  const reportArray = [];
  const xAxisTimes = getxAxisTimes(reports);

  for (const report of reports) {
    reportArray.push(report);
    const series = processReportToSeries(report, xAxisTimes);
    seriesArray.push(series.cpuValues);
    seriesArray.push(series.memoryValues);
  }

  return {
    reports: reportArray,
    xData: xAxisTimes,
    yData: seriesArray,
  };
}

function getxAxisTimes(reports: CompleteReport) {
  const xAxisTimes = new Set<number>();

  for (const report of reports.values()) {
    for (const entry of report.entries) {
      xAxisTimes.add(entry.time);
    }
  }

  const asArray = Array.from(xAxisTimes);
  asArray.sort();

  return asArray;
}

function baseUrl(): string {
  if (window.location.port === "5173") {
    return "http://localhost:3000";
  }
  return "";
}

export async function fetchReportNames(): Promise<string[]> {
  if (BUNDLED_REPORTS.length > 0) {
    return BUNDLED_REPORTS.map((r) => r.name);
  }
  const response = await fetch(`${baseUrl()}/view/profiles.json`);
  if (response.status !== 200) {
    console.log(response.status);
    alert("Error fetching server reports");
    console.log(await response.text());
  }
  return z.array(z.string()).parse(await response.json());
}

export async function fetchReportByName(name: string) {
  if (BUNDLED_REPORTS.length > 0) {
    const report = BUNDLED_REPORTS.find((r) => r.name === name);
    if (report === undefined) {
      console.log(BUNDLED_REPORTS);
      alert(`Report '${name}' not found`);
      throw new Error(`Report '${name}' not found`);
    }
    const parts = new Blob([
      Uint8Array.from(atob(report.data), (c) => c.charCodeAt(0)),
    ])
      .stream()
      .pipeThrough(new DecompressionStream("gzip"));
    const data = await new Response(parts).text();

    return parseJsonProcessReport(name, data);
  }

  const response = await fetch(`${baseUrl()}/view/${name}`);
  if (response.status !== 200) {
    console.log(response.status);
    alert(`Error fetching report ${name}`);
    console.log(await response.text());
  }
  return parseJsonProcessReport(name, await response.text());
}

const BUNDLED_REPORTS: { name: string; data: string }[] = [];
