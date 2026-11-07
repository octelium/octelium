import { expect, test, type Page } from "playwright/test";

const load = async (
  page: Page,
  path: string,
  authenticators?: { main?: string; items?: string[] },
) => {
  if (authenticators) {
    await page.addInitScript((value) => {
      (window as Window & { __OCTELIUM_AUTHENTICATORS__?: unknown }).__OCTELIUM_AUTHENTICATORS__ = value;
    }, authenticators);
  }
  await page.goto(path);
  await page.evaluate(() => document.fonts.ready);
};

const heading = (page: Page, name: string) =>
  page.getByRole("heading", { level: 1, name, exact: true });

const button = (page: Page, name: string | RegExp) =>
  page.getByRole("button", { name, exact: typeof name === "string" });

const failRequests = (page: Page) =>
  page.route("**/octelium.api.main.auth.v1.MainService/**", (route) =>
    route.fulfill({ status: 500 }),
  );

const logo = (page: Page) => page.locator('main svg[viewBox="0 0 7616 7616"]');

const pages = [
  ["/denied", "Access denied"],
  ["/callback/success/approval", "Approve this sign-in"],
  ["/authenticators", "Your Authenticators"],
  ["/authenticators/authenticate", "Your Authenticators"],
  ["/authenticators/register", "Register an Authenticator"],
  ["/does-not-exist", "We could not load this page"],
] as const;

for (const [path, title] of pages) {
  test(`${path} follows the login design at every width`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await load(page, path);
    await expect(heading(page, title)).toBeVisible();
    await expect(heading(page, title)).toHaveCSS("font-family", /^"Plus Jakarta Sans"/);
    await expect(heading(page, title)).toHaveCSS("font-weight", "700");
    await expect(logo(page)).toHaveCSS("box-shadow", /rgba\(15, 23, 42/);
    await expect(logo(page).locator("path").first()).toHaveCSS("fill", "rgb(24, 24, 27)");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);
  });
}

test("hides the logo circle in the dark theme on every page", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  for (const [path, title] of pages) {
    await load(page, path);
    await expect(heading(page, title)).toBeVisible();
    await expect(logo(page).locator("path").first()).toHaveCSS("fill", "rgba(0, 0, 0, 0)");
  }
});

test("points a denied User to the Portal", async ({ page }) => {
  await load(page, "/denied");
  await expect(page.getByText("You are not authorized to access this resource.")).toBeVisible();
  const link = page.getByRole("link", { name: "Go to the Octelium Portal" });
  await expect(link).toHaveAttribute("href", /^http:\/\/127\.0\.0\.1:4175$/);
  await expect(link).toHaveCSS("background-color", "rgb(24, 24, 27)");
  await expect(link).toHaveCSS("padding-top", "14px");
});

test("explains that a client is asking to sign in", async ({ page }) => {
  await load(page, "/callback/success/approval");
  const description = page.getByText("A client running on this device is asking to sign in.", { exact: true });
  await expect(description).toBeVisible();
  await expect(description).toHaveCSS("font-weight", "500");
});

for (const [name, pending, other, isApproved] of [
  ["Approve", "Approving…", "Reject", true],
  ["Reject", "Rejecting…", "Approve", false],
] as const) {
  test(`shows progress only on the ${name} button`, async ({ page }) => {
    let body: unknown;
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route("**/callback/success/approval", async (route) => {
      if (route.request().method() !== "POST") {
        return route.continue();
      }
      body = route.request().postDataJSON();
      await held;
      return route.fulfill({ status: 500 });
    });
    await load(page, "/callback/success/approval");
    await button(page, name).click();
    await expect(button(page, pending)).toBeDisabled();
    await expect(button(page, other)).toBeDisabled();
    expect(body).toEqual({ isApproved });
    release();
    await expect(button(page, name)).toBeEnabled();
  });
}

test("gives the Reject button a white background and a border only in the light theme", async ({ page }) => {
  await load(page, "/callback/success/approval");
  const reject = button(page, "Reject");
  await expect(reject).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await expect(reject).toHaveCSS("border-color", "rgb(203, 213, 225)");
  await expect(reject).toHaveCSS("border-width", "1px");
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.locator("html")).toHaveAttribute("data-mantine-color-scheme", "dark");
  await expect(reject).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
});

test("lists Authenticators with their type and actions", async ({ page }) => {
  await load(page, "/authenticators");
  await expect(page.getByText("Google Authenticator")).toBeVisible();
  await expect(page.getByText("totp-1")).toBeVisible();
  await expect(page.getByText(/^TOTP · Created/)).toBeVisible();
  await expect(page.getByText(/^FIDO · Created/)).toBeVisible();
  await expect(button(page, "Authenticate")).toHaveCount(1);
  await expect(button(page, "Delete")).toHaveCount(2);
  await expect(page.getByRole("link", { name: "Register an Authenticator" }))
    .toHaveAttribute("href", "/authenticators/register");
  await expect(page.getByRole("link", { name: "Return to Portal" })).toBeVisible();
});

test("uses the same dark color for every filled button", async ({ page }) => {
  await load(page, "/authenticators");
  await expect(button(page, "Authenticate")).toHaveCSS("background-color", "rgb(24, 24, 27)");
  await expect(button(page, "Authenticate")).toHaveCSS("font-weight", "700");
  await expect(button(page, "Authenticate")).toHaveCSS("box-shadow", /rgba\(15, 23, 42/);
});

test("shows the code input when authenticating from the list", async ({ page }) => {
  await load(page, "/authenticators");
  await button(page, "Authenticate").click();
  await expect(page.getByRole("spinbutton")).toHaveCount(6);
  await expect(page.getByRole("spinbutton").first()).toHaveAttribute("placeholder", "");
  await button(page, "Cancel").click();
  await expect(page.getByRole("spinbutton")).toHaveCount(0);
});

test("renames an Authenticator inline", async ({ page }) => {
  await load(page, "/authenticators");
  await button(page, "Edit Display Name").first().click();
  const input = page.getByRole("textbox", { name: "Authenticator display name" });
  await expect(input).toHaveValue("Google Authenticator");
  await input.fill("Work phone");
  await expect(page.getByRole("button", { name: "Save Display Name" })).toBeEnabled();
  await input.fill(" ");
  await expect(page.getByRole("button", { name: "Save Display Name" })).toBeDisabled();
});

test("confirms before deleting an Authenticator", async ({ page }) => {
  await load(page, "/authenticators");
  await button(page, "Delete").first().click();
  const dialog = page.getByRole("dialog", { name: "Delete this Authenticator?" });
  await expect(dialog).toContainText("Google Authenticator");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
});

test("reports a failed delete", async ({ page }) => {
  await failRequests(page);
  await load(page, "/authenticators");
  await button(page, "Delete").first().click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("alert"))
    .toHaveText("Could not delete the Authenticator. Please try again.");
});

test("offers to register the first Authenticator", async ({ page }) => {
  await load(page, "/authenticators", { items: [] });
  await expect(heading(page, "No Authenticators yet")).toBeVisible();
  await page.getByRole("link", { name: "Register an Authenticator" }).click();
  await expect(heading(page, "Register an Authenticator")).toBeVisible();
});

test("labels the main Authenticator of the Session", async ({ page }) => {
  await load(page, "/authenticators", { main: "totp-1" });
  await expect(page.getByRole("heading", { name: "Your Session's Main Authenticator" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Your Available Authenticators" })).toBeVisible();
});

test("asks for a code from the main TOTP Authenticator", async ({ page }) => {
  await failRequests(page);
  await load(page, "/authenticators/authenticate", { main: "totp-1" });
  await expect(heading(page, "Verify your identity")).toBeVisible();
  await expect(page.locator("header")).toContainText("Google Authenticator");
  const inputs = page.getByRole("spinbutton");
  await expect(inputs).toHaveCount(6);
  await expect(inputs.first()).toBeFocused();
  await page.keyboard.type("123456");
  await expect(page.getByRole("alert")).toHaveText("Could not verify the code. Please try again.");
  await expect(inputs.first()).toHaveValue("");
});

test("offers a retry when the main FIDO Authenticator fails", async ({ page }) => {
  await failRequests(page);
  await load(page, "/authenticators/authenticate", { main: "fido-1" });
  await expect(heading(page, "Verify your identity")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Authentication was not completed" })).toBeVisible();
  await expect(button(page, "Try again")).toBeVisible();
});

test("registers a TOTP Authenticator with a QR code and a setup link", async ({ page }) => {
  await load(page, "/authenticators/register");
  await expect(page.getByRole("textbox", { name: "Display name (optional)" })).toBeVisible();
  await button(page, /^TOTP/).click();
  await expect(heading(page, "Scan the QR code")).toBeVisible();
  await expect(page.locator("main svg").nth(1)).toBeVisible();
  await expect(page.getByRole("link", { name: "Open the setup link" }))
    .toHaveAttribute("href", "https://example.com");
  await expect(page.getByRole("spinbutton")).toHaveCount(6);
});

test("describes both kinds of Authenticators", async ({ page }) => {
  await load(page, "/authenticators/register");
  await expect(button(page, /^TOTP/)).toContainText("Google Authenticator");
  await expect(button(page, /^FIDO/)).toContainText("Windows Hello");
  await expect(button(page, /^TOTP/)).toHaveCSS("background-color", "rgb(24, 24, 27)");
});

test("offers a retry when FIDO registration fails", async ({ page }) => {
  await failRequests(page);
  await load(page, "/authenticators/register");
  await button(page, /^FIDO/).click();
  await expect(heading(page, "Registration was not completed")).toBeVisible();
  await expect(button(page, "Try again")).toBeVisible();
  await expect(page.getByRole("link", { name: "Return to Portal" })).toBeVisible();
});

test("offers a way out of a failed route", async ({ page }) => {
  await load(page, "/does-not-exist");
  await expect(page.getByText("The page you requested could not be found.")).toBeVisible();
  await expect(button(page, "Try again")).toBeVisible();
  await expect(page.getByRole("link", { name: "Return to login" })).toHaveAttribute("href", "/login");
});
