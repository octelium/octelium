import { expect, test, type Page } from "playwright/test";

const providers = (...names: string[]) =>
  names.map((displayName, index) => ({ uid: `idp-${index}`, displayName }));

const load = async (page: Page, state?: unknown, path = "/login") => {
  if (state) {
    await page.addInitScript((value) => {
      (window as Window & { __OCTELIUM_STATE__?: unknown }).__OCTELIUM_STATE__ = value;
    }, state);
  }
  await page.goto(path);
  await page.getByRole("heading", { name: "Sign in to Octelium" }).waitFor();
};

const button = (page: Page, name: string) =>
  page.getByRole("button", { name, exact: true });

const style = (page: Page, name: string, property: "backgroundColor" | "boxShadow") =>
  button(page, name).evaluate(
    (element, key) => getComputedStyle(element)[key],
    property,
  );

const useDarkTheme = async (page: Page) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");
};

test("fits on the screen", async ({ page }) => {
  for (const [width, height] of [[1280, 720], [390, 780]]) {
    await page.setViewportSize({ width, height });
    await load(page);
    await expect(page.getByRole("separator")).toHaveText("or");
    await expect(button(page, "Continue with a passkey")).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollHeight))
      .toBeLessThanOrEqual(height);
  }
});

test("stays usable on the smallest screens", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await load(page, {
    domain: "a-very-long-cluster-domain-name.internal.example.com",
    identityProviders: providers("A Very Long Corporate Identity Provider Name"),
    isPasskeyLoginEnabled: true,
  });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);
});

test("uses dark buttons with a shadow in the light theme", async ({ page }) => {
  await load(page);
  for (const name of ["Continue with GitHub", "Continue with Gitlab", "Continue with a passkey"]) {
    expect(await style(page, name, "backgroundColor")).toBe("rgb(24, 24, 27)");
    expect(await style(page, name, "boxShadow")).toContain("rgba(15, 23, 42");
  }
});

test("uses bold button labels with a slow transition", async ({ page }) => {
  await load(page);
  const signIn = button(page, "Continue with GitHub");
  await expect(signIn).toHaveCSS("font-weight", "700");
  await expect(signIn).toHaveCSS("transition-duration", "0.5s");
});

test("gives the buttons comfortable vertical padding", async ({ page }) => {
  await load(page);
  const signIn = button(page, "Continue with GitHub");
  await expect(signIn).toHaveCSS("padding-top", "14px");
  await expect(signIn).toHaveCSS("padding-bottom", "14px");
  expect((await signIn.boundingBox())?.height).toBeGreaterThanOrEqual(52);
});

test("uses Plus Jakarta Sans with extra word spacing", async ({ page }) => {
  await load(page);
  await page.waitForFunction(() =>
    [...document.fonts].some(
      (font) => font.family.includes("Plus Jakarta Sans") && font.status === "loaded",
    ),
  );
  for (const element of [
    page.getByRole("heading", { name: "Sign in to Octelium" }),
    button(page, "Continue with GitHub"),
  ]) {
    await expect(element).toHaveCSS("font-family", /^"Plus Jakarta Sans"/);
  }
  await expect(button(page, "Continue with GitHub")).toHaveCSS("word-spacing", "0.96px");
});

test("shows a solid logo circle with a shadow only in the light theme", async ({ page }) => {
  await load(page);
  const logo = page.locator('main svg[viewBox="0 0 7616 7616"]');
  const disc = logo.locator("path").first();
  await expect(logo).toHaveCSS("background-image", "none");
  await expect(disc).toHaveCSS("fill", "rgb(24, 24, 27)");
  await expect(logo).toHaveCSS("box-shadow", /rgba\(15, 23, 42/);
  await expect(logo).not.toHaveCSS("box-shadow", /inset/);
  await useDarkTheme(page);
  await expect(disc).toHaveCSS("fill", "rgba(0, 0, 0, 0)");
  await expect(logo).toHaveCSS("box-shadow", /^(rgba\(0, 0, 0, 0\) 0px 0px 0px 0px(, )?)+$/);
  await expect(logo.locator("path").last()).toHaveCSS("fill", "rgb(255, 255, 255)");
});

for (const [viewport, size] of [
  [{ width: 390, height: 500 }, 104],
  [{ width: 390, height: 780 }, 144.296875],
  [{ width: 1440, height: 900 }, 166.5],
  [{ width: 1440, height: 1200 }, 168],
] as const) {
  test(`sizes the logo for a ${viewport.width}x${viewport.height} screen`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await load(page);
    const box = await page.locator('main svg[viewBox="0 0 7616 7616"]').boundingBox();
    expect(box?.width).toBe(size);
    expect(box?.height).toBe(size);
  });
}

test("does not turn the only sign-in method white in the dark theme", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await load(page);
  const background = await style(page, "Continue with a passkey", "backgroundColor");
  expect(background).not.toBe("rgb(255, 255, 255)");

  for (const [state, name] of [
    [{ domain: "example.com", isPasskeyLoginEnabled: true }, "Continue with a passkey"],
    [{ domain: "example.com", identityProviders: providers("Okta") }, "Continue with Okta"],
  ] as const) {
    await load(page, state);
    await expect(button(page, name)).toHaveClass(/dark:bg-surface/);
    await expect.poll(() => style(page, name, "backgroundColor")).toBe(background);
    await expect(page.getByRole("separator")).toHaveCount(0);
  }
});

test("keeps the only sign-in method dark in the light theme", async ({ page }) => {
  await load(page);
  const background = await style(page, "Continue with a passkey", "backgroundColor");

  await load(page, { domain: "example.com", isPasskeyLoginEnabled: true });
  await expect
    .poll(() => style(page, "Continue with a passkey", "backgroundColor"))
    .toBe(background);
});

test("gives several sign-in methods equal weight in the dark theme", async ({ page }) => {
  await load(page);
  await useDarkTheme(page);
  for (const name of ["Continue with GitHub", "Continue with Gitlab", "Continue with a passkey"]) {
    await expect(button(page, name)).toHaveClass(/dark:bg-surface/);
    await expect.poll(() => style(page, name, "boxShadow")).not.toContain("rgba(15, 23, 42");
  }
});

test("gives unknown Identity Providers an icon", async ({ page }) => {
  await load(page, { domain: "example.com", identityProviders: providers("Corporate SSO") });
  await expect(button(page, "Continue with Corporate SSO").locator("svg")).toBeVisible();
});

test("explains when there is no way to sign in", async ({ page }) => {
  await load(page, { domain: "example.com" });
  await expect(page.getByText(/No sign-in methods are available/)).toBeVisible();
  await expect(page.getByRole("main").getByRole("button")).toHaveCount(0);
});

test("reports a failed sign-in attempt", async ({ page }) => {
  await load(page, undefined, "/login?error=1");
  await expect(page.getByRole("alert")).toHaveText(
    "We could not start sign-in. Please try again.",
  );
  await expect(page).toHaveURL(/\/login$/);
});

test("shows the sign-in that is in progress", async ({ page }) => {
  await page.route("**/begin", () => {});
  await load(page);
  await button(page, "Continue with GitHub").click();
  const pending = button(page, "Redirecting to GitHub…");
  await expect(pending).toHaveAttribute("aria-busy", "true");
  await expect(pending).toBeDisabled();
  await expect(button(page, "Continue with Gitlab")).toBeDisabled();
  await expect(button(page, "Continue with a passkey")).toBeDisabled();
});

test("sends the original query when beginning a sign-in", async ({ page }) => {
  let body: { uid?: string; query?: string } = {};
  await page.route("**/begin", async (route) => {
    body = route.request().postDataJSON();
    await route.fulfill({ status: 500 });
  });
  await load(page, undefined, "/login?redirect=abc");
  await button(page, "Continue with GitHub").click();
  await expect.poll(() => body.uid).toBe("github");
  expect(body.query).toBe("redirect=abc");
});

test("uses a neutral palette in the dark theme", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await load(page);
  const spreads = await page.evaluate(() => {
    const context = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
    const probe = document.createElement("div");
    document.body.append(probe);
    const read = (name: string) => {
      probe.style.backgroundColor = `var(${name})`;
      context.fillStyle = getComputedStyle(probe).backgroundColor;
      context.fillRect(0, 0, 1, 1);
      const [red, green, blue] = context.getImageData(0, 0, 1, 1).data;
      return Math.max(red, green, blue) - Math.min(red, green, blue);
    };
    return ["--portal-canvas", "--portal-surface", "--portal-line", "--portal-fg", "--portal-fg-subtle"].map(read);
  });
  for (const spread of spreads) {
    expect(spread).toBeLessThanOrEqual(3);
  }
});
