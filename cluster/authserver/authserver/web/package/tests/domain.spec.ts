import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "playwright/test";
import { build, preview, type PreviewServer } from "vite";

type AuthDomain = {
  getDomain: () => string;
  getPortalURL: () => string;
  isDev: () => boolean;
  transportOptions: () => {
    baseUrl: string;
    fetchInit?: RequestInit;
  };
  requestAvailableAuthenticator: () => Promise<unknown>;
};

declare global {
  interface Window {
    authDomain: AuthDomain;
  }
}

const root = fileURLToPath(new URL("../", import.meta.url));
const modes = ["production", "development"] as const;

test.describe("Login cluster domain", () => {
  test.describe.configure({ mode: "serial" });

  let directory: string;
  const servers = new Map<(typeof modes)[number], PreviewServer>();
  let errors: string[];

  test.beforeAll(async () => {
    test.setTimeout(120_000);
    directory = await mkdtemp(join(tmpdir(), "authserver-domain-"));
    for (const mode of modes) {
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
  });

  test.afterAll(async () => {
    for (const server of servers.values()) await server.close();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  test.beforeEach(async ({ page }) => {
    errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
  });

  test.afterEach(() => {
    expect(errors).toEqual([]);
  });

  const load = async (
    page: Page,
    mode: (typeof modes)[number],
    globals: unknown,
  ) => {
    await page.addInitScript((globals) => {
      if (globals === undefined) {
        delete (window as { __OCTELIUM_GLOBALS__?: unknown })
          .__OCTELIUM_GLOBALS__;
      } else {
        (window as { __OCTELIUM_GLOBALS__?: unknown }).__OCTELIUM_GLOBALS__ =
          globals;
      }
    }, globals);
    const origin = servers.get(mode)!.resolvedUrls!.local[0];
    await page.goto(`${origin}tests/fixtures/domain.html`);
    await page.waitForFunction(() => window.authDomain);
  };

  const injectDomainCookie = async (page: Page) => {
    await page.addInitScript(() => {
      document.cookie = "octelium_domain=attacker.example.test; path=/";
    });
  };

  test("uses the server domain without a domain cookie", async ({ page }) => {
    await load(page, "production", { cluster: { domain: "example.test" } });
    const result = await page.evaluate(() => ({
      domain: window.authDomain.getDomain(),
      portalURL: window.authDomain.getPortalURL(),
      cookie: document.cookie,
    }));
    expect(result.domain).toBe("example.test");
    expect(result.portalURL).toBe("https://portal.example.test");
    expect(result.cookie).toBe("");
  });

  test("uses the server domain for credentialed RPCs and portal links despite an injected domain cookie", async ({
    page,
  }) => {
    await injectDomainCookie(page);
    await load(page, "production", { cluster: { domain: "example.test" } });
    const result = await page.evaluate(async () => {
      const requests: { url: string; credentials?: RequestCredentials }[] =
        [];
      const originalFetch = window.fetch;
      window.fetch = async (url, init) => {
        requests.push({ url: String(url), credentials: init?.credentials });
        const trailer = new TextEncoder().encode("grpc-status: 0\r\n");
        return new Response(
          new Uint8Array([
            0, 0, 0, 0, 0, 128, 0, 0, 0, trailer.length, ...trailer,
          ]),
          { headers: { "content-type": "application/grpc-web+proto" } },
        );
      };
      try {
        await window.authDomain.requestAvailableAuthenticator();
      } finally {
        window.fetch = originalFetch;
      }
      document.cookie = "octelium_domain=other.example.test; path=/";
      return {
        requests,
        domain: window.authDomain.getDomain(),
        portalURL: window.authDomain.getPortalURL(),
        isDev: window.authDomain.isDev(),
        cookie: document.cookie,
      };
    });
    expect(result.isDev).toBe(false);
    expect(result.domain).toBe("example.test");
    expect(result.portalURL).toBe("https://portal.example.test");
    expect(result.cookie).toContain("octelium_domain=other.example.test");
    expect(result.requests).toHaveLength(1);
    expect(result.requests[0].url).toMatch(
      /^http:\/\/octelium-api\.example\.test\/.*\/GetAvailableAuthenticator$/,
    );
    expect(result.requests[0].credentials).toBe("include");
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
    test(`rejects invalid server globals ${JSON.stringify(globals)} without trusting the cookie`, async ({
      page,
    }) => {
      await injectDomainCookie(page);
      await load(page, "production", globals);
      const result = await page.evaluate(() =>
        [
          () => window.authDomain.getDomain(),
          () => window.authDomain.transportOptions(),
          () => window.authDomain.getPortalURL(),
        ].map((call) => {
          try {
            call();
            return "unexpected domain";
          } catch (error) {
            return (error as Error).message;
          }
        }),
      );
      expect(result).toEqual([
        "The cluster domain is unavailable",
        "The cluster domain is unavailable",
        "The cluster domain is unavailable",
      ]);
    });
  }

  test("keeps development RPCs and portal links on the current host without server globals", async ({
    page,
  }) => {
    await injectDomainCookie(page);
    await load(page, "development", undefined);
    const result = await page.evaluate(() => ({
      domain: window.authDomain.getDomain(),
      portalURL: window.authDomain.getPortalURL(),
      isDev: window.authDomain.isDev(),
      options: window.authDomain.transportOptions(),
    }));
    const url = new URL(page.url());
    expect(result.isDev).toBe(true);
    expect(result.domain).toBe(url.host);
    expect(result.portalURL).toBe(url.origin);
    expect(result.options.baseUrl).toBe(url.origin);
    expect(result.options.fetchInit?.credentials).toBe("include");
  });
});
