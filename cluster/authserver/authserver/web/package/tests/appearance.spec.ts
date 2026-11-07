import { expect, test, type Page } from "playwright/test";

const appearance = (page: Page) =>
  page.getByRole("radiogroup", { name: "Appearance" });

const choose = (page: Page, label: string) =>
  appearance(page).locator("label").filter({ hasText: label }).click();

const scheme = (page: Page) => page.locator("html");

for (const width of [320, 768, 1280]) {
  test(`login layout stays consistent across themes at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/login");
    await page.evaluate(() => document.fonts.ready);

    const logo = page.locator('main svg[viewBox="0 0 7616 7616"]');
    const signIn = page.getByRole("button", { name: "Continue with GitHub", exact: true });
    const lightLayout = await Promise.all([
      logo.boundingBox(),
      signIn.boundingBox(),
    ]);

    expect(lightLayout[0]?.width).toBe(width < 640 ? 80 : 96);

    await choose(page, "Dark");
    await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "dark");

    expect(await Promise.all([
      logo.boundingBox(),
      signIn.boundingBox(),
    ])).toEqual(lightLayout);

    await choose(page, "Light");
    await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "light");
    expect(await signIn.boundingBox()).toEqual(lightLayout[1]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);

    for (const icon of await appearance(page).locator("svg").all()) {
      await expect(icon).toHaveCSS("width", "14px");
      await expect(icon).toHaveCSS("height", "14px");
    }
  });
}

test("appearance is always visible and shows the current choice", async ({ page }) => {
  await page.goto("/login");
  await expect(appearance(page)).toBeVisible();
  await expect(appearance(page).getByRole("radio", { name: "System" })).toBeChecked();

  await choose(page, "Dark");
  await expect(appearance(page).getByRole("radio", { name: "Dark" })).toBeChecked();
  await expect(appearance(page)).toBeVisible();
});

test("explicit themes persist and System follows device preferences", async ({ page }) => {
  await page.goto("/login");

  for (const [label, value, deviceScheme] of [
    ["Dark", "dark", "light"],
    ["Light", "light", "dark"],
  ] as const) {
    await choose(page, label);
    await page.emulateMedia({ colorScheme: deviceScheme });
    await page.reload();
    await expect(appearance(page).getByRole("radio", { name: label })).toBeChecked();
    await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", value);
  }

  await choose(page, "System");
  await expect(appearance(page).getByRole("radio", { name: "System" })).toBeChecked();
  await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "dark");

  await page.emulateMedia({ colorScheme: "light" });
  await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "light");
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "dark");
  await page.reload();
  await expect(appearance(page).getByRole("radio", { name: "System" })).toBeChecked();
  await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "dark");
});

test("appearance supports keyboard selection with visible focus", async ({ page }) => {
  await page.goto("/login");

  await page.getByRole("link", { name: "Octelium home" }).focus();
  await page.keyboard.press("Tab");
  await expect(appearance(page).getByRole("radio", { name: "System" })).toBeFocused();

  for (const label of ["Dark", "Light", "System"]) {
    await page.keyboard.press("ArrowLeft");
    await expect(appearance(page).getByRole("radio", { name: label, exact: true })).toBeChecked();
    await expect(appearance(page).getByRole("radio", { name: label, exact: true })).toBeFocused();
    await expect(appearance(page).locator("label").filter({ hasText: label })).toHaveCSS("outline-style", "solid");
  }
});

test.describe("touch appearance control", () => {
  test.use({ viewport: { width: 320, height: 800 }, isMobile: true, hasTouch: true });

  test("a single tap changes the appearance", async ({ page }) => {
    await page.goto("/login");
    const option = appearance(page).locator("label").filter({ hasText: "Dark" });
    const optionLayout = await option.boundingBox();
    expect(optionLayout?.width).toBeGreaterThanOrEqual(40);
    expect(optionLayout?.height).toBeGreaterThanOrEqual(40);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);

    await option.tap();
    await expect(scheme(page)).toHaveAttribute("data-mantine-color-scheme", "dark");
    await expect(appearance(page).getByRole("radio", { name: "Dark" })).toBeChecked();
  });
});
