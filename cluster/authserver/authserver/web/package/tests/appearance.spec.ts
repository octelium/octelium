import { expect, test } from "playwright/test";

for (const width of [320, 768, 1280]) {
  test(`login layout stays consistent across themes at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/login");
    await page.evaluate(() => document.fonts.ready);

    const appearance = page.getByRole("radiogroup", { name: "Appearance" });
    const trigger = page.getByRole("button", { name: /^Appearance:/ });
    const logo = page.locator('svg[viewBox="0 0 256 256"]');
    const wrapper = logo.locator("..");
    const signIn = page.getByRole("button", { name: "GitHub", exact: true });
    const lightLayout = await Promise.all([
      wrapper.boundingBox(),
      logo.boundingBox(),
      signIn.boundingBox(),
    ]);

    expect(lightLayout[0]?.width).toBe(width < 768 ? 160 : 240);
    expect(lightLayout[1]?.width).toBe(width < 768 ? 80 : 160);

    await trigger.click();
    await appearance.locator("label").filter({ hasText: "Dark" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");

    expect(await Promise.all([
      wrapper.boundingBox(),
      logo.boundingBox(),
      signIn.boundingBox(),
    ])).toEqual(lightLayout);
    await expect(wrapper).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");

    await wrapper.hover();
    await expect(wrapper).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");

    await trigger.click();
    await appearance.locator("label").filter({ hasText: "Light" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "light");
    expect(await signIn.boundingBox()).toEqual(lightLayout[2]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);

    await trigger.click();
    for (const icon of await appearance.locator("svg").all()) {
      await expect(icon).toHaveCSS("width", "13px");
      await expect(icon).toHaveCSS("height", "13px");
    }
  });
}

test("explicit themes persist and System follows device preferences", async ({ page }) => {
  await page.goto("/login");
  const appearance = page.getByRole("radiogroup", { name: "Appearance" });
  const trigger = page.getByRole("button", { name: /^Appearance:/ });

  for (const [label, scheme, deviceScheme] of [
    ["Dark", "dark", "light"],
    ["Light", "light", "dark"],
  ] as const) {
    await trigger.click();
    await appearance.locator("label").filter({ hasText: label }).click();
    await page.emulateMedia({ colorScheme: deviceScheme });
    await page.reload();
    await expect(trigger).toHaveAccessibleName(`Appearance: ${label}. Change appearance`);
    await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", scheme);
  }

  await trigger.click();
  await appearance.locator("label").filter({ hasText: "System" }).click();
  await expect(trigger).toHaveAccessibleName("Appearance: System. Change appearance");
  await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");

  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "light");
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");
  await page.reload();
  await expect(trigger).toHaveAccessibleName("Appearance: System. Change appearance");
  await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");
});

test("appearance supports keyboard selection with visible focus", async ({ page }) => {
  await page.goto("/login");
  const appearance = page.getByRole("radiogroup", { name: "Appearance" });
  const trigger = page.getByRole("button", { name: /^Appearance:/ });

  await page.getByRole("link", { name: "Octelium home" }).focus();
  await page.keyboard.press("Tab");
  await expect(trigger).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(appearance).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(appearance.getByRole("radio", { name: "System" })).toBeFocused();

  for (const label of ["Dark", "Light", "System"]) {
    await page.keyboard.press("ArrowLeft");
    await expect(appearance.getByRole("radio", { name: label, exact: true })).toBeChecked();
    await expect(appearance.getByRole("radio", { name: label, exact: true })).toBeFocused();
    await expect(appearance.locator("label").filter({ hasText: label })).toHaveCSS("outline-style", "solid");
  }

  await page.keyboard.press("Escape");
  await expect(appearance).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("appearance stays compact and expands to the left on hover", async ({ page }) => {
  await page.goto("/login");
  const trigger = page.getByRole("button", { name: /^Appearance:/ });
  const appearance = page.getByRole("radiogroup", { name: "Appearance" });
  const brand = page.getByRole("link", { name: "Octelium home" });
  const brandLayout = await brand.boundingBox();
  const triggerLayout = await trigger.boundingBox();

  expect(triggerLayout?.width).toBe(32);
  await expect(trigger.locator("svg")).toHaveCSS("width", "13px");
  await expect(appearance).toBeHidden();
  await trigger.hover();
  await expect(appearance).toBeVisible();
  const expandedLayout = await appearance.boundingBox();
  expect(expandedLayout!.x + expandedLayout!.width).toBeLessThanOrEqual(triggerLayout!.x);
  expect(await trigger.boundingBox()).toEqual(triggerLayout);
  expect(await brand.boundingBox()).toEqual(brandLayout);

  await appearance.locator("label").filter({ hasText: "Dark" }).hover();
  await expect(appearance).toBeVisible();
  await page.mouse.move(0, 100);
  await expect(appearance).toBeHidden();
});

test.describe("touch appearance control", () => {
  test.use({ viewport: { width: 320, height: 800 }, isMobile: true, hasTouch: true });

  test("tap opens, selects, and dismisses without hover", async ({ page }) => {
    await page.goto("/login");
    const trigger = page.getByRole("button", { name: /^Appearance:/ });
    const appearance = page.getByRole("radiogroup", { name: "Appearance" });

    await expect(appearance).toBeHidden();
    await trigger.tap();
    await expect(appearance).toBeVisible();
    const option = appearance.locator("label").filter({ hasText: "Dark" });
    const optionLayout = await option.boundingBox();
    expect(optionLayout?.width).toBeGreaterThanOrEqual(40);
    expect(optionLayout?.height).toBeGreaterThanOrEqual(40);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);

    await option.tap();
    await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");
    await expect(appearance).toBeHidden();
    await expect(trigger).toHaveAccessibleName("Appearance: Dark. Change appearance");

    await trigger.tap();
    await expect(appearance).toBeVisible();
    await appearance.locator("label").filter({ hasText: "Dark" }).tap();
    await expect(appearance).toBeHidden();

    await trigger.tap();
    await expect(appearance).toBeVisible();
    await page.getByRole("heading").tap();
    await expect(appearance).toBeHidden();
  });
});
