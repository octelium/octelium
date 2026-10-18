import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { build, preview } from "vite";

const root = fileURLToPath(new URL("../", import.meta.url));

describe("Portal cluster domain", () => {
  let directory;
  let browser;
  let context;
  let page;
  let errors;
  const servers = new Map();

  before(async () => {
    directory = await mkdtemp(join(tmpdir(), "portal-domain-"));
    for (const mode of ["production", "development"]) {
      const outDir = join(directory, mode);
      await build({
        root,
        mode,
        logLevel: "silent",
        build: {
          outDir,
          rolldownOptions: {
            input: join(root, "tests/fixtures/domain.html"),
          },
        },
      });
      servers.set(
        mode,
        await preview({
          root,
          logLevel: "silent",
          build: { outDir },
          preview: { host: "127.0.0.1", port: 0 },
        }),
      );
    }
    browser = await chromium.launch();
  });

  after(async () => {
    await browser?.close();
    for (const server of servers.values())
      await new Promise((resolve) => server.httpServer.close(resolve));
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    context = await browser.newContext();
    page = await context.newPage();
    page.setDefaultTimeout(10_000);
    errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
  });

  afterEach(async () => {
    await context?.close();
    assert.deepEqual(errors, []);
  });

  const load = async (mode, globals) => {
    await page.addInitScript((globals) => {
      if (globals === undefined) {
        delete window.__OCTELIUM_GLOBALS__;
      } else {
        window.__OCTELIUM_GLOBALS__ = globals;
      }
    }, globals);
    const origin = servers.get(mode).resolvedUrls.local[0];
    await page.goto(`${origin}tests/fixtures/domain.html`);
    await page.waitForFunction(() => window.portalDomain);
  };

  it("uses the server domain without a domain cookie", async () => {
    await load("production", { cluster: { domain: "example.test" } });
    const result = await page.evaluate(() => ({
      domain: window.portalDomain.getDomain(),
      portalURL: window.portalDomain.getPortalURL("/authenticators"),
      cookie: document.cookie,
    }));
    assert.equal(result.domain, "example.test");
    assert.equal(result.portalURL, "https://example.test/authenticators");
    assert.equal(result.cookie, "");
  });

  it("uses the server domain for credentialed RPCs and portal links despite an injected domain cookie", async () => {
    await page.addInitScript(() => {
      document.cookie = "octelium_domain=namespace.example.test; path=/";
    });
    await load("production", { cluster: { domain: "example.test" } });
    const result = await page.evaluate(async () => {
      const requests = [];
      const originalFetch = window.fetch;
      window.fetch = async (url, init) => {
        requests.push({ url, credentials: init.credentials });
        const trailer = new TextEncoder().encode("grpc-status: 0\r\n");
        return new Response(
          new Uint8Array([
            0, 0, 0, 0, 0, 128, 0, 0, 0, trailer.length, ...trailer,
          ]),
          { headers: { "content-type": "application/grpc-web+proto" } },
        );
      };
      try {
        await window.portalDomain.requestStatus();
      } finally {
        window.fetch = originalFetch;
      }
      document.cookie = "octelium_domain=other.example.test; path=/";
      return {
        requests,
        domain: window.portalDomain.getDomain(),
        portalURL: window.portalDomain.getPortalURL("/authenticators"),
        isDev: window.portalDomain.isDev(),
        cookie: document.cookie,
      };
    });
    assert.equal(result.isDev, false);
    assert.equal(result.domain, "example.test");
    assert.equal(result.portalURL, "https://example.test/authenticators");
    assert.ok(result.cookie.includes("octelium_domain=other.example.test"));
    assert.equal(result.requests.length, 1);
    assert.ok(
      result.requests[0].url.startsWith("http://octelium-api.example.test/"),
    );
    assert.ok(result.requests[0].url.endsWith("/GetStatus"));
    assert.equal(result.requests[0].credentials, "include");
  });

  for (const globals of [
    undefined,
    null,
    {},
    { cluster: null },
    { cluster: {} },
    { cluster: { domain: "" } },
    { cluster: { domain: 123 } },
  ]) {
    it(`rejects invalid server globals ${JSON.stringify(globals)} without trusting the cookie`, async () => {
      await page.addInitScript(() => {
        document.cookie = "octelium_domain=namespace.example.test; path=/";
      });
      await load("production", globals);
      const result = await page.evaluate(() =>
        [
          () => window.portalDomain.transportOptions(),
          () => window.portalDomain.getPortalURL("/authenticators"),
        ].map((call) => {
          try {
            call();
            return "unexpected domain";
          } catch (error) {
            return error.message;
          }
        }),
      );
      assert.deepEqual(result, [
        "The cluster domain is unavailable",
        "The cluster domain is unavailable",
      ]);
    });
  }

  it("keeps development RPCs and portal links on the current host without server globals", async () => {
    await page.addInitScript(() => {
      document.cookie = "octelium_domain=namespace.example.test; path=/";
    });
    await load("development", undefined);
    const result = await page.evaluate(() => ({
      domain: window.portalDomain.getDomain(),
      portalURL: window.portalDomain.getPortalURL("/authenticators"),
      isDev: window.portalDomain.isDev(),
      options: window.portalDomain.transportOptions(),
    }));
    assert.equal(result.isDev, true);
    assert.equal(result.domain, new URL(page.url()).host);
    assert.equal(
      result.portalURL,
      `${new URL(page.url()).origin}/authenticators`,
    );
    assert.equal(result.options.baseUrl, new URL(page.url()).origin);
    assert.equal(result.options.fetchInit.credentials, "include");
  });
});
