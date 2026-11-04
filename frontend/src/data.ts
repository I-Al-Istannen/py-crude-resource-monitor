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
  short_filename: z.string().nullable(),
  line: z.number(),
  locals: z.null().optional(), // Only captured when dumping locals, which we never enable
  is_entry: z.boolean(),
});
export type StackFrame = z.infer<typeof StackFrameSchema>;

export const ThreadDumpSchema = z.object({
  pid: z.number(),
  thread_id: z.number(),
  thread_name: z.string().nullable(),
  os_thread_id: z.number().nullable(),
  active: z.boolean(),
  owns_gil: z.boolean(),
  // The frames, innermost first. Resolved from `stack` while parsing, older reports store them in
  // every sample.
  frames: z.array(StackFrameSchema).default([]),
  // The stack of the thread, see `parseJsonProcessReport`. Missing if it has no frames.
  stack: z.number().nullish(),
  process_info: z.null().optional(), // Never set by py-spy's PythonSpy, only by its own sampler
});
export type ThreadDump = z.infer<typeof ThreadDumpSchema>;

const StackSchema = z.object({
  stack: z.number(),
  parent: z.number().nullable(),
  frame: z.number(),
});

export const ProcessReportEntrySchema = z.object({
  stacktraces: z.array(ThreadDumpSchema),
  // Set if capturing the stacktraces failed for this sample. Missing in older reports.
  stacktrace_error: z.string().nullish(),
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

/**
 * Parses a sample file. Frames and stacks are written once, each in their own line before the
 * first sample using them, and samples reference the stack of every thread by its id:
 *
 *   {"frame":0,"name":"<module>","filename":"/w/main.py",...}
 *   {"stack":0,"parent":null,"frame":0}
 *   {"stacktraces":[{"thread_id":1,...,"stack":0}],"resources":{...},...}
 *
 * A stack is its innermost frame on top of the stack of its caller (`parent`).
 */
export function parseJsonProcessReport(
  id: ProcessId,
  reportString: string
): ProcessReport {
  const entries = [];
  const frames: StackFrame[] = [];
  // The resolved frames of every stack, innermost first
  const stacks: StackFrame[][] = [];

  for (const line of reportString.split("\n")) {
    if (!line) {
      continue;
    }
    const json = JSON.parse(line);
    // Stack lines also have a "frame" key, so check for them first
    if ("stack" in json) {
      const stack = StackSchema.parse(json);
      const callers = stack.parent === null ? [] : stacks[stack.parent];
      const frame = frames[stack.frame];
      if (stack.stack !== stacks.length || callers === undefined || frame === undefined) {
        throw new Error(`Invalid stack in ${id}: ${line}`);
      }
      stacks.push([frame, ...callers]);
    } else if ("frame" in json) {
      if (json.frame !== frames.length) {
        throw new Error(`Invalid frame in ${id}: ${line}`);
      }
      frames.push(StackFrameSchema.parse(json));
    } else {
      const entry = ProcessReportEntrySchema.parse(json);
      for (const thread of entry.stacktraces) {
        if (thread.stack != null) {
          const resolved = stacks[thread.stack];
          if (resolved === undefined) {
            throw new Error(`Unknown stack ${thread.stack} in ${id}`);
          }
          thread.frames = resolved;
        }
      }
      entries.push(entry);
    }
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
  const indexByTime = new Map(xAxisTimes.map((time, index) => [time, index]));
  // Times without a sample (e.g. before the process started) stay null
  const memoryValues: (number | null)[] = new Array(xAxisTimes.length).fill(null);
  const cpuValues: (number | null)[] = new Array(xAxisTimes.length).fill(null);

  for (const entry of report.entries) {
    const index = indexByTime.get(entry.time);
    if (index === undefined) {
      continue;
    }
    memoryValues[index] = entry.resources.memory;
    cpuValues[index] = entry.resources.cpu;
  }

  return {
    cpuValues,
    memoryValues,
  };
}

export function completeReportToSeries(reports: CompleteReport): PlotData {
  const seriesArray = [];
  const xAxisTimes = getxAxisTimes(reports);

  // Sort them to allow easy visual binary search in the legend
  const reportArray = reports
    .slice()
    .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

  for (const report of reportArray) {
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

  for (const report of reports) {
    for (const entry of report.entries) {
      xAxisTimes.add(entry.time);
    }
  }

  return Array.from(xAxisTimes).sort((a, b) => a - b);
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
    console.log(await response.text());
    alert("Error fetching server reports");
    throw new Error(`Fetching report names failed with status ${response.status}`);
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
    console.log(await response.text());
    alert(`Error fetching report ${name}`);
    throw new Error(`Fetching report ${name} failed with status ${response.status}`);
  }
  return parseJsonProcessReport(name, await response.text());
}

const BUNDLED_REPORTS: { name: string; data: string }[] = [];
