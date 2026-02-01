/**
 * Test Utilities
 *
 * Custom render function that wraps components with necessary providers.
 * Use this instead of @testing-library/react's render for component tests.
 */
import { render, type RenderOptions } from "@testing-library/react";
import { type ReactElement, type ReactNode } from "react";

import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";

/**
 * Props for the AllProviders wrapper component
 */
interface AllProvidersProps {
  children: ReactNode;
}

/**
 * Wraps children with all necessary providers for testing
 */
function AllProviders({ children }: AllProvidersProps): ReactElement {
  return (
    <ThemeProvider>
      <TooltipProvider>{children}</TooltipProvider>
    </ThemeProvider>
  );
}

/**
 * Custom render function that includes all providers
 *
 * @param ui - The React element to render
 * @param options - Additional render options
 * @returns Render result with all queries
 *
 * @example
 * ```tsx
 * import { render, screen } from "@/__tests__/utils/test-utils";
 *
 * render(<MyComponent />);
 * expect(screen.getByText("Hello")).toBeInTheDocument();
 * ```
 */
const customRender = (
  ui: ReactElement,
  options?: Omit<RenderOptions, "wrapper">
) => render(ui, { wrapper: AllProviders, ...options });

// Re-export everything from testing-library
export * from "@testing-library/react";
export { userEvent } from "@testing-library/user-event";

// Override render with our custom version
export { customRender as render };
