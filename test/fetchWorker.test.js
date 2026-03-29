import { createFetchWorker, FetchWorkerFilter } from "../esm/fetchWorker.js";
import { serializeHeaders } from "./esm/utils.js";

describe("createFetchWorker", () => {
  let worker: Worker;
  let fetchWorker: ReturnType<typeof createFetchWorker>;

  beforeEach(() => {
    worker = new Worker("worker.js");
    fetchWorker = createFetchWorker(worker);
  });

  afterEach(() => {
    worker.terminate();
  });

  it("should use fallback fetch for filtered URLs", async () => {
    const fallbackFetch = jest.fn().mockResolvedValue(new Response("fallback"));
    const filter: FetchWorkerFilter = (url) => url.startsWith("http");

    fetchWorker = createFetchWorker(worker, filter, fallbackFetch);

    const response = await fetchWorker("http://example.com");
    const text = await response.text();

    expect(fallbackFetch).toHaveBeenCalledWith("http://example.com", undefined);
    expect(text).toBe("fallback");
  });

  it("should throw error if filtered URL and no fallback fetch", async () => {
    const filter: FetchWorkerFilter = (url) => url.startsWith("http");

    fetchWorker = createFetchWorker(worker, filter);

    await expect(fetchWorker("http://example.com")).rejects.toThrow(
      "Blocked by FetchWorker filter"
    );
  });

  it("should send fetch request to worker for non-filtered URLs", async () => {
    const filter: FetchWorkerFilter = (url) => !url.startsWith("http");

    fetchWorker = createFetchWorker(worker, filter);

    const mockResponse = {
      type: "response",
      id: 0,
      data: {
        body: "worker response",
        headers: serializeHeaders({ "Content-Type": "text/plain" }),
        status: 200,
        statusText: "OK",
      },
    };

    worker.postMessage = jest.fn((message) => {
      if (message.type === "fetch") {
        worker.dispatchEvent(new MessageEvent("message", { data: mockResponse }));
      }
    });

    const response = await fetchWorker("/api/data");
    const text = await response.text();

    expect(text).toBe("worker response");
  });

  it("should handle abort signal", async () => {
    const filter: FetchWorkerFilter = (url) => !url.startsWith("http");

    fetchWorker = createFetchWorker(worker, filter);

    const controller = new AbortController();
    const signal = controller.signal;

    const fetchPromise = fetchWorker("/api/data", { signal });

    controller.abort();

    await expect(fetchPromise).rejects.toThrow("Aborted");
  });
});
