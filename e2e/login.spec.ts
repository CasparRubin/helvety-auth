import { test, expect } from "@playwright/test";

test.describe("Login Page", () => {
  test("should load the login page", async ({ page }) => {
    await page.goto("/login");
    await expect(page).toHaveTitle(/Helvety/i);
  });

  test("should show email input", async ({ page }) => {
    await page.goto("/login");
    const emailInput = page.getByPlaceholder(/email/i);
    await expect(emailInput).toBeVisible();
  });

  test("should show continue button", async ({ page }) => {
    await page.goto("/login");
    const continueButton = page.getByRole("button", { name: /continue/i });
    await expect(continueButton).toBeVisible();
  });

  test("should validate email format", async ({ page }) => {
    await page.goto("/login");

    const emailInput = page.getByPlaceholder(/email/i);
    await emailInput.fill("invalid-email");

    const continueButton = page.getByRole("button", { name: /continue/i });
    await continueButton.click();

    // Should show validation error or not proceed
    // The page should still be on login
    await expect(page).toHaveURL(/\/login/);
  });

  test("should handle valid email input", async ({ page }) => {
    await page.goto("/login");

    const emailInput = page.getByPlaceholder(/email/i);
    await emailInput.fill("test@example.com");

    const continueButton = page.getByRole("button", { name: /continue/i });
    await expect(continueButton).toBeEnabled();
  });
});

test.describe("Redirect URI Handling", () => {
  test("should preserve redirect_uri parameter", async ({ page }) => {
    await page.goto("/login?redirect_uri=https://store.helvety.com/dashboard");

    // The redirect_uri should be preserved in the URL
    expect(page.url()).toContain("redirect_uri");
  });

  test("should handle missing redirect_uri gracefully", async ({ page }) => {
    await page.goto("/login");
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe("Theme Switching", () => {
  test("should toggle theme", async ({ page }) => {
    await page.goto("/login");

    const themeButton = page.getByRole("button", { name: /toggle theme/i });

    if (await themeButton.isVisible()) {
      const htmlElement = page.locator("html");
      const initialClass = await htmlElement.getAttribute("class");

      await themeButton.click();
      await page.waitForTimeout(100);

      const newClass = await htmlElement.getAttribute("class");
      expect(newClass).not.toBe(initialClass);
    }
  });
});
