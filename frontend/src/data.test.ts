import { describe, expect, test } from "vitest";
import {
  completeReportToSeries,
  parseJsonProcessReport,
  ProcessReport,
  ProcessReportEntry,
} from "./data";

function entry(time: number, cpu: number): ProcessReportEntry {
  return {
    stacktraces: [],
    resources: { memory: cpu * 10, cpu_core_percent: cpu },
    index: 0,
    time,
  };
}

function report(id: string, entries: ProcessReportEntry[]): ProcessReport {
  return { id, entries };
}

describe("completeReportToSeries", () => {
  test("aligns samples with gaps to the right times", () => {
    const data = completeReportToSeries([
      report("1.json", [entry(1000, 10), entry(3000, 30)]),
      report("global.json", [entry(1000, 1), entry(2000, 2), entry(3000, 3)]),
    ]);

    expect(data.xData).toEqual([1000, 2000, 3000]);
    expect(data.yData[0]).toEqual([10, null, 30]);
    expect(data.yData[1]).toEqual([100, null, 300]);
  });

  test("pads processes that start late and end early", () => {
    const data = completeReportToSeries([
      report("1.json", [entry(2000, 20)]),
      report("global.json", [entry(1000, 1), entry(2000, 2), entry(3000, 3)]),
    ]);

    expect(data.yData[0]).toEqual([null, 20, null]);
  });

  test("sorts times numerically", () => {
    const data = completeReportToSeries([
      report("1.json", [entry(900, 1), entry(1000, 2), entry(10000, 3)]),
    ]);

    expect(data.xData).toEqual([900, 1000, 10000]);
  });

  test("sorts reports by numeric pid", () => {
    const data = completeReportToSeries([
      report("100.json", [entry(1000, 1)]),
      report("global.json", [entry(1000, 1)]),
      report("20.json", [entry(1000, 1)]),
    ]);

    expect(data.reports.map((it) => it.id)).toEqual([
      "20.json",
      "100.json",
      "global.json",
    ]);
  });

  test("handles empty reports", () => {
    const data = completeReportToSeries([
      report("1.json", []),
      report("global.json", [entry(1000, 1)]),
    ]);

    expect(data.yData[0]).toEqual([null]);
  });
});

describe("parseJsonProcessReport", () => {
  test("accepts a missing os thread id and stacktrace errors", () => {
    const line = {
      stacktraces: [
        {
          pid: 1,
          thread_id: 2,
          thread_name: null,
          os_thread_id: null,
          active: true,
          owns_gil: false,
          frames: [],
          process_info: null,
        },
      ],
      resources: { memory: 1, cpu_core_percent: 2 },
      index: 0,
      time: 1000,
    };
    const failed = {
      stacktraces: [],
      stacktrace_error: "process went away",
      resources: { memory: 1, cpu_core_percent: 2 },
      index: 1,
      time: 2000,
    };

    const parsed = parseJsonProcessReport(
      "1.json",
      `${JSON.stringify(line)}\n${JSON.stringify(failed)}\n`
    );

    expect(parsed.entries).toHaveLength(2);
    expect(parsed.entries[0].stacktraces[0].os_thread_id).toBeNull();
    expect(parsed.entries[1].stacktrace_error).toBe("process went away");
  });

  test("resolves the stacks of threads", () => {
    const frame = (frame: number, name: string, line: number) => ({
      frame,
      name,
      filename: "/w/main.py",
      module: null,
      short_filename: "main.py",
      line,
      is_entry: false,
    });
    const thread = (stack: number | null) => ({
      pid: 1,
      thread_id: 2,
      thread_name: "MainThread",
      os_thread_id: 2,
      active: true,
      owns_gil: true,
      stack,
    });
    const sample = (index: number, stacks: (number | null)[]) => ({
      stacktraces: stacks.map(thread),
      resources: { memory: 1, cpu_core_percent: 2 },
      index,
      time: 1000 * index,
    });
    const lines = [
      frame(0, "main", 1),
      { stack: 0, parent: null, frame: 0 },
      frame(1, "work", 5),
      { stack: 1, parent: 0, frame: 1 },
      sample(0, [1, null]),
      frame(2, "idle", 9),
      { stack: 2, parent: 0, frame: 2 },
      sample(1, [2, 1]),
    ];

    const parsed = parseJsonProcessReport(
      "1.json",
      lines.map((it) => JSON.stringify(it)).join("\n")
    );

    const names = parsed.entries.map((entry) =>
      entry.stacktraces.map((it) => it.frames.map((f) => `${f.name}:${f.line}`))
    );
    expect(names).toEqual([
      [["work:5", "main:1"], []],
      [["idle:9", "main:1"], ["work:5", "main:1"]],
    ]);
  });

  test("skips an incomplete last line", () => {
    const sample = JSON.stringify({
      stacktraces: [],
      resources: { memory: 1, cpu_core_percent: 2 },
      index: 0,
      time: 1000,
    });

    const parsed = parseJsonProcessReport("1.json", `${sample}\n${sample.slice(0, 20)}`);

    expect(parsed.entries).toHaveLength(1);
  });
});


describe("CPU recording units", () => {
  test("normalizes core units only for display", () => {
    const parsed = parseJsonProcessReport("1.json", JSON.stringify({
      ...entry(1000, 200),
      resources: { memory: 1024, cpu_core_percent: 200, cpus: 4 },
    }) + "\n");
    expect(parsed.entries[0].resources.cpu_core_percent).toBe(200);
    expect(completeReportToSeries([parsed]).yData[0]).toEqual([50]);
  });
});
