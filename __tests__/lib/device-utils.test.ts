import { describe, it, expect, afterEach } from "vitest";

import { isMobileDevice } from "@/lib/device-utils";

describe("device-utils", () => {
  const originalWindow = global.window;

  afterEach(() => {
    if (originalWindow) {
      global.window = originalWindow;
    }
  });

  describe("isMobileDevice", () => {
    it("should return false when window is undefined (SSR)", () => {
      // @ts-expect-error - Intentionally setting window to undefined
      delete global.window;
      expect(isMobileDevice()).toBe(false);
    });

    it("should return false when viewport is wide and pointer is not coarse", () => {
      Object.defineProperty(global, "window", {
        value: {
          matchMedia: (_query: string) => ({
            matches: false,
          }),
        },
        writable: true,
        configurable: true,
      });
      (global as { navigator?: { maxTouchPoints?: number } }).navigator = {
        maxTouchPoints: 0,
      };
      expect(isMobileDevice()).toBe(false);
    });

    it("should return true when viewport is narrow (max-width: 768px)", () => {
      Object.defineProperty(global, "window", {
        value: {
          matchMedia: (query: string) => ({
            matches: query === "(max-width: 768px)",
          }),
        },
        writable: true,
        configurable: true,
      });
      (global as { navigator?: { maxTouchPoints?: number } }).navigator = {
        maxTouchPoints: 0,
      };
      expect(isMobileDevice()).toBe(true);
    });

    it("should return true when pointer is coarse and has touch", () => {
      Object.defineProperty(global, "window", {
        value: {
          matchMedia: (query: string) => ({
            matches: query === "(pointer: coarse)",
          }),
        },
        writable: true,
        configurable: true,
      });
      (global as { navigator?: { maxTouchPoints?: number } }).navigator = {
        maxTouchPoints: 5,
      };
      expect(isMobileDevice()).toBe(true);
    });
  });
});
