import { expect, test } from "playwright/test";

for (const width of [320, 1280]) {
  test(`error notifications follow theme changes at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route("**/begin", (route) => route.fulfill({ status: 500 }));
    await page.goto("/login");
    await page.getByRole("button", { name: "GitHub", exact: true }).click();

    const notification = page.getByRole("alert");
    await expect(notification).toHaveText("Could not login. Please try again.");

    for (const label of ["Light", "Dark", "Light"]) {
      await page.getByRole("button", { name: /^Appearance:/ }).click();
      await page.getByRole("radiogroup", { name: "Appearance" })
        .locator("label").filter({ hasText: label }).click();
      await expect(page.locator("html")).toHaveAttribute(
        "data-mantine-color-scheme", label.toLowerCase(),
      );
      await notification.hover();

      const colors = await page.evaluate(() => {
        const probe = document.createElement("div");
        probe.style.backgroundColor = "var(--portal-surface)";
        probe.style.borderColor = "var(--portal-line)";
        probe.style.color = "var(--portal-fg)";
        document.body.append(probe);
        const styles = getComputedStyle(probe);
        const colors = {
          surface: styles.backgroundColor,
          border: styles.borderColor,
          foreground: styles.color,
          muted: "",
          error: "",
        };
        probe.style.color = "var(--portal-fg-muted)";
        colors.muted = styles.color;
        probe.style.color = "var(--mantine-color-red-filled)";
        colors.error = styles.color;
        probe.remove();
        return colors;
      });

      await expect(notification).toHaveCSS("background-color", colors.surface);
      await expect(notification).toHaveCSS("border-color", colors.border);
      await expect(notification.locator(".mantine-Notification-description"))
        .toHaveCSS("color", colors.foreground);
      await expect(notification.getByRole("button", { name: "Dismiss notification" }))
        .toHaveCSS("color", colors.muted);
      expect(await notification.evaluate((element) =>
        getComputedStyle(element, "::before").backgroundColor,
      )).toBe(colors.error);

      const bounds = (await notification.boundingBox())!;
      expect(Math.round(bounds.x + bounds.width / 2)).toBe(width / 2);
      expect(bounds.x).toBeGreaterThan(0);
      expect(bounds.x + bounds.width).toBeLessThan(width);
      expect(900 - bounds.y - bounds.height).toBeGreaterThanOrEqual(0);
      expect(900 - bounds.y - bounds.height).toBeLessThanOrEqual(32);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
    }

    await notification.getByRole("button", { name: "Dismiss notification" }).click();
    await expect(notification).toHaveCount(0);
  });
}

test("error notifications close automatically after four seconds", async ({ page }) => {
  await page.clock.install();
  await page.route("**/begin", (route) => route.fulfill({ status: 500 }));
  await page.goto("/login");
  await page.getByRole("button", { name: "GitHub", exact: true }).click();
  const notification = page.getByRole("alert");
  await expect(notification).toBeVisible();

  await page.clock.runFor(4500);
  await expect(notification).toHaveCount(0);
});

test("approval failures display a dismissible error notification", async ({ page }) => {
  await page.route("**/callback/success/approval", (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({ status: 500 });
    }
    return route.continue();
  });
  await page.goto("/callback/success/approval");
  const approve = page.getByRole("button", { name: "Approve", exact: true });
  await approve.click();
  const notification = page.getByRole("alert");
  await expect(notification).toHaveText("Could not complete the request. Please try again.");
  await expect(approve).toBeEnabled();
  await notification.getByRole("button", { name: "Dismiss notification" }).click();
  await expect(notification).toHaveCount(0);
});
