import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium, firefox } from "playwright";
import { createServer } from "vite";

const root = fileURLToPath(new URL("../", import.meta.url));
const storageKey = "octelium-portal-color-scheme";
const itemsPerPageKey = "octelium-portal-items-per-page";

for (const [name, browserType] of Object.entries({ chromium, firefox })) {
  describe(`Portal in ${name}`, () => {
    let cacheDir;
    let server;
    let browser;
    let context;
    let page;
    let origin;
    let errors;

    before(async () => {
      cacheDir = await mkdtemp(join(root, "node_modules/.vite-portal-"));
      server = await createServer({
        root,
        cacheDir,
        logLevel: "error",
        optimizeDeps: {
          entries: ["tests/fixtures/portal.tsx", "src/**/*.tsx"],
          include: ["react/jsx-runtime"],
        },
        plugins: [
          {
            name: "portal-test-entry",
            transformIndexHtml: {
              order: "pre",
              handler: (html) =>
                html.replace("/src/main.tsx", "/tests/fixtures/portal.tsx"),
            },
          },
        ],
        server: { host: "127.0.0.1", port: 0, watch: null, hmr: false },
      });
      await server.listen();
      origin = server.resolvedUrls.local[0].replace(/\/$/, "");
      browser = await browserType.launch();
    });

    after(async () => {
      await browser?.close();
      await server?.close();
      if (cacheDir) await rm(cacheDir, { recursive: true, force: true });
    });

    beforeEach(async () => {
      context = await browser.newContext({
        colorScheme: "dark",
        reducedMotion: "reduce",
        viewport: { width: 1440, height: 1000 },
      });
      page = await context.newPage();
      page.setDefaultTimeout(15_000);
      errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      page.on("console", (message) => {
        if (message.type() === "error") errors.push(message.text());
      });
    });

    afterEach(async () => {
      await context?.close();
      assert.deepEqual(errors, []);
    });

    const load = async (path = "/services", fixture) => {
      if (fixture) {
        await page.addInitScript((value) => {
          window.portalFixture = value;
        }, fixture);
      }
      await page.goto(`${origin}${path}`);
      await page.getByRole("heading", { level: 1 }).waitFor();
    };

    const requests = (method) =>
      page.evaluate(
        (value) =>
          window.calls
            .filter((call) => call.method === value)
            .map((call) => call.request),
        method,
      );

    const lastRequest = async (method) => (await requests(method)).at(-1);

    const scheme = () =>
      page.locator("html").getAttribute("data-mantine-color-scheme");

    const services = () =>
      page.getByRole("list", { name: "Services", exact: true });

    const rows = () => services().getByRole("listitem");

    const waitForRows = async (count) => {
      await services().waitFor();
      await page.waitForFunction(
        (value) =>
          document.querySelectorAll('ul[aria-label="Services"] > li').length ===
          value,
        count,
      );
    };

    const readNames = () =>
      [...document.querySelectorAll('ul[aria-label="Services"] > li')].map(
        (item) =>
          item
            .querySelector('button[aria-label*="details of "]')
            ?.getAttribute("aria-label")
            .replace(/^(Show|Hide) details of /, ""),
      );

    const rowNames = () => page.evaluate(readNames);

    const waitForNames = async (names) => {
      const deadline = Date.now() + 15_000;
      let actual = await rowNames();
      while (
        JSON.stringify(actual) !== JSON.stringify(names) &&
        Date.now() < deadline
      ) {
        await page.waitForTimeout(50);
        actual = await rowNames();
      }
      assert.deepEqual(actual, names);
    };

    it("redirects to the Services and lists them by name", async () => {
      await load("/");
      assert.equal(new URL(page.url()).pathname, "/services");
      await waitForRows(10);
      assert.deepEqual((await rowNames()).slice(0, 3), [
        "api",
        "billing.production",
        "clickhouse.data",
      ]);
      await page.getByText("1–10 of 16", { exact: true }).waitFor();
      assert.equal(await page.title(), "Services · Octelium Portal");
      const request = await lastRequest("listService");
      assert.equal(request.common.itemsPerPage, 10);
      assert.deepEqual(request.common.orderBy, { type: "NAME", mode: "ASC" });

      const content = await rows().first().textContent();
      for (const text of ["Type: HTTP", "Namespace: default", "Port: 8080"]) {
        assert.ok(content.includes(text), `${text} in ${content}`);
      }
      assert.equal(
        await page
          .getByRole("link", { name: "Services", exact: true })
          .getAttribute("aria-current"),
        "page",
      );
    });

    it("searches across names, descriptions and Namespaces", async () => {
      await load();
      await waitForRows(10);
      await page.keyboard.press("/");
      const search = page.getByRole("textbox", {
        name: "Search Services",
        exact: true,
      });
      assert.equal(
        await search.evaluate((element) => element === document.activeElement),
        true,
      );

      await search.fill("payments");
      await page.waitForURL((url) => url.searchParams.get("q") === "payments");
      await waitForNames(["billing.production"]);
      assert.equal(
        await rows().first().locator("mark").textContent(),
        "Payments",
      );
      assert.equal((await lastRequest("listService")).common.itemsPerPage, 500);
      await page
        .getByText("1 of 16 Services matches", { exact: true })
        .waitFor();

      await search.fill("staging ssh");
      await page.waitForURL(
        (url) => url.searchParams.get("q") === "staging ssh",
      );
      await waitForNames(["ssh-bastion.staging"]);

      await search.press("Escape");
      await page.waitForURL((url) => !url.searchParams.has("q"));
      await waitForRows(10);

      await search.fill("nothing-matches-this");
      await page.getByText("No matching Services", { exact: true }).waitFor();
      await page
        .getByRole("button", { name: "Clear filters", exact: true })
        .first()
        .click();
      await waitForRows(10);
      assert.equal(await search.inputValue(), "");
    });

    it("keeps the filters usable when an element denies access to its shadowRoot", async () => {
      await load();
      await waitForRows(10);
      await page.evaluate(() => {
        const forbidden = document.createElement("div");
        Object.defineProperty(forbidden, "shadowRoot", {
          get() {
            throw new Error(
              'Permission denied to access property "shadowRoot"',
            );
          },
        });
        document.body.append(forbidden);
      });

      const namespace = page.getByRole("combobox", {
        name: "Filter by Namespace",
        exact: true,
      });
      await namespace.fill("missing");
      await namespace.fill("prod");
      await page
        .getByRole("option", { name: "production (Production)", exact: true })
        .click();
      await page.waitForURL(
        (url) => url.searchParams.get("namespace") === "production",
      );
      await waitForRows(5);

      await page
        .getByRole("combobox", { name: "Filter by type", exact: true })
        .click();
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
      await page.waitForURL((url) => url.searchParams.has("type"));

      await page
        .getByRole("button", { name: "Clear filters", exact: true })
        .click();
      await waitForRows(10);
      await page
        .getByRole("combobox", { name: "Per page", exact: true })
        .click();
      await page.getByRole("option", { name: "20", exact: true }).click();
      await waitForRows(16);
      await page
        .getByRole("heading", { name: "Services", exact: true })
        .waitFor();
    });

    it("searches shadow roots while skipping inaccessible hosts", async () => {
      await load();
      const result = await page.evaluate(async () => {
        const {
          findElementBySelector,
          findElementsBySelector,
          getRootElement,
        } = await import("/src/utils/mantine/find-element-in-shadow-dom.js");
        const host = document.createElement("div");
        const shadow = host.attachShadow({ mode: "open" });
        const forbidden = document.createElement("div");
        Object.defineProperty(forbidden, "shadowRoot", {
          get() {
            throw new Error("Denied");
          },
        });
        shadow.append(forbidden);
        const nested = document.createElement("div");
        const child = nested.attachShadow({ mode: "open" });
        child.innerHTML = '<span class="target">Found</span>';
        shadow.append(nested);
        document.body.append(host);
        return [
          findElementBySelector(".target", shadow)?.textContent,
          findElementsBySelector(".target", shadow).length,
          getRootElement(child.querySelector("span")) === child,
          findElementBySelector(".missing"),
          findElementsBySelector(".missing").length,
        ];
      });
      assert.deepEqual(result, ["Found", 1, true, null, 0]);
    });

    it("filters by Namespace and type and clears filters", async () => {
      await load();
      await waitForRows(10);

      const namespace = page.getByRole("combobox", {
        name: "Filter by Namespace",
        exact: true,
      });
      await namespace.click();
      assert.equal(
        await page
          .getByRole("option", { name: "octelium", exact: true })
          .count(),
        0,
      );
      await page
        .getByRole("option", { name: "production (Production)", exact: true })
        .click();
      await page.waitForURL(
        (url) => url.searchParams.get("namespace") === "production",
      );
      await waitForRows(5);
      assert.equal((await lastRequest("listService")).namespace, "production");

      const type = page.getByRole("combobox", {
        name: "Filter by type",
        exact: true,
      });
      await type.click();
      await page.getByRole("option", { name: "HTTP", exact: true }).click();
      await page.waitForURL((url) => url.searchParams.get("type") === "HTTP");
      await waitForRows(1);
      assert.equal((await lastRequest("listService")).type, "HTTP");

      await page
        .getByRole("button", {
          name: "Remove the Namespace filter",
          exact: true,
        })
        .click();
      await page.waitForURL((url) => !url.searchParams.has("namespace"));
      await waitForNames(["api", "billing.production"]);

      await page
        .getByRole("button", { name: "Clear filters", exact: true })
        .click();
      await page.waitForURL((url) => !url.searchParams.has("type"));
      await waitForRows(10);
    });

    it("filters from the labels of a Service", async () => {
      await load();
      await waitForRows(10);
      await page
        .getByRole("link", {
          name: "Show only the Services of the staging Namespace",
          exact: true,
        })
        .first()
        .click();
      await page.waitForURL(
        (url) => url.searchParams.get("namespace") === "staging",
      );
      await waitForRows(2);
      assert.equal(
        await page
          .getByRole("link", {
            name: "Show only the Services of the staging Namespace",
          })
          .count(),
        0,
      );

      await page
        .getByRole("link", { name: "Show only SSH Services", exact: true })
        .click();
      await page.waitForURL((url) => url.searchParams.get("type") === "SSH");
      await waitForNames(["ssh-bastion.staging"]);
    });

    it("expands a Service to show how to connect to it", async () => {
      await load("/services?namespace=production&type=POSTGRES");
      await waitForRows(1);
      const row = rows().first();
      const toggle = row.getByRole("button", {
        name: "Show details of postgres.production",
        exact: true,
      });
      assert.equal(await toggle.getAttribute("aria-expanded"), "false");
      await toggle.click();

      const host = new URL(origin).host;
      await row
        .getByText(`postgres.production.local.${host}`, { exact: true })
        .waitFor();
      await row
        .getByText("postgres.production", { exact: true })
        .last()
        .waitFor();
      assert.match(
        await row.locator("pre").innerText(),
        /^\$ psql -h postgres\.production$/,
      );
      assert.equal(
        await row
          .getByRole("button", {
            name: "Hide details of postgres.production",
            exact: true,
          })
          .getAttribute("aria-expanded"),
        "true",
      );

      await row.locator(".font-semibold").first().click();
      await row.locator("pre").waitFor({ state: "detached" });
    });

    it("types the connection command when motion is allowed", async () => {
      await page.emulateMedia({ reducedMotion: "no-preference" });
      await load("/services?type=SSH");
      await waitForRows(1);
      const row = rows().first();
      await row
        .getByRole("button", { name: "Show details of ssh-bastion.staging" })
        .click();
      const terminal = row.getByRole("group", { name: "Connect with ssh" });
      await terminal.waitFor();
      assert.equal(
        await terminal.locator("pre").innerText(),
        "$ ssh ssh-bastion.staging",
      );
      await terminal.locator(".animate-terminal-caret").waitFor();
      assert.equal(await terminal.locator("pre .opacity-0").count(), 0);
      assert.equal(
        await terminal.locator("pre .font-semibold").innerText(),
        "ssh",
      );
    });

    it(
      "copies the connection command",
      { skip: name !== "chromium" },
      async () => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"]);
        await load("/services?type=SSH");
        await waitForRows(1);
        await rows()
          .first()
          .getByRole("button", { name: "Show details of ssh-bastion.staging" })
          .click();
        await page
          .getByRole("button", { name: "Copy command", exact: true })
          .click();
        await page
          .getByRole("button", { name: "Copied", exact: true })
          .waitFor();
        assert.equal(
          await page.evaluate(() => navigator.clipboard.readText()),
          "ssh ssh-bastion.staging",
        );
      },
    );

    it("offers to open only public web Services", async () => {
      await load();
      await waitForRows(10);
      const open = page.getByRole("link", { name: /^Open .* in a new tab$/ });
      assert.equal(await open.count(), 2);
      const host = new URL(origin).host;
      assert.equal(
        await page
          .getByRole("link", { name: "Open demo-nginx in a new tab" })
          .getAttribute("href"),
        `https://demo-nginx.${host}`,
      );
      assert.equal(
        await page
          .getByRole("link", { name: "Open grafana.staging in a new tab" })
          .getAttribute("target"),
        "_blank",
      );
    });

    it("paginates and remembers the page size", async () => {
      await load();
      await waitForRows(10);
      await page
        .getByRole("navigation", { name: "Pagination" })
        .getByRole("button", { name: "2", exact: true })
        .click();
      await page.waitForURL(
        (url) => url.searchParams.get("common.page") === "1",
      );
      await waitForRows(6);
      await page.getByText("11–16 of 16", { exact: true }).waitFor();
      assert.equal((await lastRequest("listService")).common.page, 1);

      await page
        .getByRole("combobox", { name: "Per page", exact: true })
        .click();
      await page.getByRole("option", { name: "20", exact: true }).click();
      await page.waitForURL((url) => !url.searchParams.has("common.page"));
      await waitForRows(16);
      assert.equal(
        await page.evaluate(
          (key) => localStorage.getItem(key),
          itemsPerPageKey,
        ),
        "20",
      );

      await page.reload();
      await waitForRows(16);
      assert.equal((await lastRequest("listService")).common.itemsPerPage, 20);
    });

    it("recovers from a failed request", async () => {
      await load("/services", { failServices: 1 });
      await page
        .getByText("Could not load Services", { exact: true })
        .waitFor();
      await page
        .getByText("You do not have permission to view this information.", {
          exact: true,
        })
        .waitFor();
      await page
        .getByRole("button", { name: "Try again", exact: true })
        .click();
      await waitForRows(10);
    });

    it("explains when no Services are available", async () => {
      await load("/services", { empty: true });
      await page.getByText("No Services available", { exact: true }).waitFor();
      assert.equal(
        await page.getByRole("button", { name: "Clear filters" }).count(),
        0,
      );
    });

    it("browses Namespaces and their Services", async () => {
      await load("/namespaces");
      const list = page.getByRole("list", { name: "Namespaces", exact: true });
      await list.waitFor();
      assert.equal(await list.getByRole("listitem").count(), 5);

      const production = page.getByRole("link", {
        name: "production: show its Services",
        exact: true,
      });
      await page.waitForFunction(() =>
        [...document.querySelectorAll("a")].some(
          (element) =>
            element.getAttribute("aria-label") ===
              "production: show its Services" &&
            element.textContent.includes("5 Services"),
        ),
      );
      assert.match(
        await page
          .getByRole("link", { name: "octelium: show its Services" })
          .innerText(),
        /System/,
      );

      const search = page.getByRole("textbox", {
        name: "Search Namespaces",
        exact: true,
      });
      await search.fill("analytics");
      await page.waitForURL((url) => url.searchParams.get("q") === "analytics");
      await page.waitForFunction(
        () =>
          document.querySelectorAll('ul[aria-label="Namespaces"] > li')
            .length === 1,
      );
      await search.press("Escape");
      await page.waitForURL((url) => !url.searchParams.has("q"));

      await production.click();
      await page.waitForURL(
        (url) =>
          url.pathname === "/services" &&
          url.searchParams.get("namespace") === "production",
      );
      await waitForRows(5);
      assert.equal(
        await page
          .getByRole("combobox", { name: "Filter by Namespace" })
          .inputValue(),
        "production (Production)",
      );
    });

    it("shows the signed-in user and the release", async () => {
      await load("/settings");
      await page.getByText("Alice Morgan", { exact: true }).first().waitFor();
      for (const text of ["alice@example.com", "example.com", "Human"]) {
        await page.getByText(text, { exact: true }).first().waitFor();
      }
      assert.match(
        await page
          .getByRole("link", { name: "Manage authenticators" })
          .getAttribute("href"),
        /\/authenticators$/,
      );
      const release = page.getByRole("link", {
        name: "Releases v0.24.0 released Oct 2, 2026",
        exact: true,
      });
      await release.waitFor();
      assert.equal(
        await release.getAttribute("href"),
        "https://github.com/octelium/octelium/releases/tag/v0.24.0",
      );
      assert.equal(
        await release.locator("time").getAttribute("datetime"),
        "2026-10-02T12:00:00Z",
      );
      for (const name of ["Documentation", "GitHub", /Octelium Labs/]) {
        assert.equal(
          await page.getByRole("link", { name }).getAttribute("rel"),
          null,
        );
      }
    });

    it("uses the system theme until a choice is saved", async () => {
      await load("/settings");
      assert.equal(await scheme(), "dark");
      assert.equal(
        await page
          .getByRole("radio", { name: "System", exact: true })
          .isChecked(),
        true,
      );
      await page.emulateMedia({ colorScheme: "light" });
      await page.waitForFunction(
        () => document.documentElement.dataset.mantineColorScheme === "light",
      );

      await page.getByText("Dark", { exact: true }).click();
      assert.equal(await scheme(), "dark");
      assert.equal(
        await page.evaluate((key) => localStorage.getItem(key), storageKey),
        "dark",
      );
      await page.reload();
      await page
        .getByRole("heading", { name: "Settings", exact: true })
        .waitFor();
      assert.equal(await scheme(), "dark");

      await page.getByText("System", { exact: true }).click();
      await page.waitForFunction(
        () => document.documentElement.dataset.mantineColorScheme === "light",
      );
    });

    it("applies a saved theme before the application starts", async () => {
      await page.route("**/tests/fixtures/portal.tsx", (route) =>
        route.abort(),
      );
      await page.addInitScript(
        (key) => localStorage.setItem(key, "light"),
        storageKey,
      );
      await page.goto(origin);
      assert.equal(await scheme(), "light");
      errors.length = 0;
    });

    it("signs out from the account menu after confirmation", async () => {
      await load();
      const menu = page.getByRole("button", {
        name: "Account menu for Alice Morgan",
        exact: true,
      });
      await menu.click();
      assert.match(
        await page
          .getByRole("menuitem", { name: "Authenticators", exact: true })
          .getAttribute("href"),
        /\/authenticators$/,
      );
      await page
        .getByRole("menuitem", { name: "Sign out", exact: true })
        .click();

      const dialog = page.getByRole("dialog", {
        name: "Sign out",
        exact: true,
      });
      await dialog.waitFor();
      await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
      await dialog.waitFor({ state: "hidden" });
      assert.equal((await requests("logout")).length, 0);

      await menu.click();
      await page
        .getByRole("menuitem", { name: "Sign out", exact: true })
        .click();
      await Promise.all([
        page.waitForEvent("load"),
        dialog.getByRole("button", { name: "Sign out", exact: true }).click(),
      ]);
      assert.equal(
        await page.evaluate(() =>
          sessionStorage.getItem("portalFixture.logouts"),
        ),
        "1",
      );
    });

    it("signs out from the sidebar after confirmation", async () => {
      await load();
      assert.match(
        await page
          .getByRole("link", { name: "Authenticators", exact: true })
          .getAttribute("href"),
        /\/authenticators$/,
      );
      const signOut = page.getByRole("button", {
        name: "Sign out",
        exact: true,
      });
      await signOut.click();

      const dialog = page.getByRole("dialog", {
        name: "Sign out",
        exact: true,
      });
      await dialog.waitFor();
      await page.keyboard.press("Escape");
      await dialog.waitFor({ state: "hidden" });
      assert.equal((await requests("logout")).length, 0);

      await signOut.click();
      await Promise.all([
        page.waitForEvent("load"),
        dialog.getByRole("button", { name: "Sign out", exact: true }).click(),
      ]);
      assert.equal(
        await page.evaluate(() =>
          sessionStorage.getItem("portalFixture.logouts"),
        ),
        "1",
      );
    });

    it("signs out from the drawer on small screens", async () => {
      await page.setViewportSize({ width: 390, height: 844 });
      await load();
      await page
        .getByRole("button", { name: "Open navigation", exact: true })
        .click();
      const drawer = page.getByRole("dialog", {
        name: "Portal navigation",
        exact: true,
      });
      await drawer.waitFor();
      assert.match(
        await drawer
          .getByRole("link", { name: "Authenticators", exact: true })
          .getAttribute("href"),
        /\/authenticators$/,
      );
      await drawer
        .getByRole("button", { name: "Sign out", exact: true })
        .click();

      const dialog = page.getByRole("dialog", {
        name: "Sign out",
        exact: true,
      });
      await dialog.waitFor();
      await page.keyboard.press("Escape");
      await dialog.waitFor({ state: "hidden" });
      assert.equal(await drawer.isVisible(), true);

      await drawer
        .getByRole("button", { name: "Sign out", exact: true })
        .click();
      await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
      await dialog.waitFor({ state: "hidden" });
      assert.equal(await drawer.isVisible(), true);
      assert.equal((await requests("logout")).length, 0);

      await drawer
        .getByRole("button", { name: "Sign out", exact: true })
        .click();
      await Promise.all([
        page.waitForEvent("load"),
        dialog.getByRole("button", { name: "Sign out", exact: true }).click(),
      ]);
      assert.equal(
        await page.evaluate(() =>
          sessionStorage.getItem("portalFixture.logouts"),
        ),
        "1",
      );
    });

    it("navigates with the drawer on small screens", async () => {
      await page.setViewportSize({ width: 390, height: 844 });
      await load();
      const open = page.getByRole("button", {
        name: "Open navigation",
        exact: true,
      });
      await open.click();
      const drawer = page.getByRole("dialog", {
        name: "Portal navigation",
        exact: true,
      });
      await drawer.waitFor();
      await drawer
        .getByRole("link", { name: "Namespaces", exact: true })
        .click();
      await page
        .getByRole("heading", { name: "Namespaces", exact: true })
        .waitFor();
      await drawer.waitFor({ state: "hidden" });
      assert.equal(await open.getAttribute("aria-expanded"), "false");
    });

    it("shows a not found page for unknown addresses", async () => {
      await load("/nope");
      await page
        .getByRole("heading", { name: "Page not found", exact: true })
        .waitFor();
      assert.equal(await page.title(), "Page not found · Octelium Portal");
      await page
        .getByRole("link", { name: "Go to Services", exact: true })
        .click();
      await waitForRows(10);
    });
  });
}
