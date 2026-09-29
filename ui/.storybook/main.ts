import path from "node:path";
import type { StorybookConfig } from "@storybook/react-vite";

const config: StorybookConfig = {
  stories: ["../src/**/*.stories.@(ts|tsx)"],
  addons: [
    "@storybook/addon-links",
    "@storybook/addon-essentials",
    "@storybook/addon-interactions",
  ],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  docs: {
    autodocs: true,
  },
  viteFinal: async (viteConfig) => {
    viteConfig.resolve = viteConfig.resolve ?? {};
    viteConfig.resolve.alias = {
      ...(viteConfig.resolve.alias as Record<string, string> | undefined),
      // Mirror the `@/*` path alias declared in `ui/tsconfig.json`.
      "@": path.resolve(__dirname, "../src"),
      // Stories render components against injected mock SDKs, so the chain SDK
      // (which lives in the repository root and is not published here) is
      // replaced with a local stub. See `.storybook/mocks/stellar-identity-sdk.ts`.
      "@stellar-identity/sdk": path.resolve(__dirname, "./mocks/stellar-identity-sdk.ts"),
    };
    return viteConfig;
  },
};

export default config;
