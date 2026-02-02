# Testing Guide

This document describes the testing patterns and conventions used in this project.

## Directory Structure

```
__tests__/
├── components/           # Component tests
├── lib/                  # Library/utility tests
│   ├── crypto/           # Encryption utility tests
│   └── auth/             # Authentication utility tests (csrf, rate-limit, auth-errors, auth-guard)
└── utils/                # Test utilities
    ├── test-utils.tsx    # Custom render with providers
    └── mock-factories.ts # Test data factories
```

## Test File Naming

- Unit tests: `*.test.ts` or `*.test.tsx`
- E2E tests: `*.spec.ts` (in `e2e/` directory)

## Running Tests

```bash
# Watch mode (recommended during development)
npm run test

# Single run
npm run test:run

# With coverage report
npm run test:coverage

# Run specific test file
npm run test -- path/to/file.test.ts

# E2E tests
npm run test:e2e
npm run test:e2e:ui  # With Playwright UI
```

## Test Structure

Use nested `describe` blocks for organization:

```typescript
describe("ModuleName", () => {
  describe("functionName", () => {
    describe("when condition", () => {
      it("should do something", () => {
        // test
      });
    });
  });
});
```

## Mocking

### Global Mocks

Global mocks are defined in `vitest.setup.ts`:
- Next.js navigation (`useRouter`, `usePathname`, etc.)
- `next-themes`
- WebAuthn APIs
- Crypto APIs
- btoa/atob polyfills

### Test-Level Mocks

Use `vi.mock()` at the top of test files:

```typescript
vi.mock("@/lib/some-module", () => ({
  someFunction: vi.fn(),
}));
```

### Mock Factories

Use factories from `utils/mock-factories.ts`:

```typescript
import { 
  createMockUser, 
  createMockSupabaseClient,
  createMockPasskeyCredential 
} from "@/__tests__/utils/mock-factories";

const user = createMockUser({ email: "custom@example.com" });
const client = createMockSupabaseClient();
const credential = createMockPasskeyCredential();
```

## Component Testing

Use the custom render from `utils/test-utils.tsx`:

```typescript
import { render, screen } from "@/__tests__/utils/test-utils";

it("should render component", () => {
  render(<MyComponent />);
  expect(screen.getByText("Hello")).toBeInTheDocument();
});
```

## Async Testing

For async operations:

```typescript
it("should handle async", async () => {
  render(<MyComponent />);
  
  await waitFor(() => {
    expect(screen.getByText("Loaded")).toBeInTheDocument();
  });
});
```

## Coverage Thresholds

The project enforces these coverage thresholds:
- Lines: 70%
- Functions: 70%
- Branches: 60%
- Statements: 70%

## Best Practices

1. **Test behavior, not implementation** - Focus on what the code does, not how it does it
2. **Use meaningful test descriptions** - Tests should read like documentation
3. **One assertion per test when possible** - Makes failures easier to diagnose
4. **Reset mocks between tests** - Use `vi.clearAllMocks()` in `beforeEach`
5. **Use screen queries** - Prefer `screen.getByRole` over `container.querySelector`
6. **Avoid testing implementation details** - Don't test private methods or state directly
