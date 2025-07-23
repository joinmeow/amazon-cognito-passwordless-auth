module.exports = {
  preset: "ts-jest",
  testEnvironment: "jsdom",
  roots: ["<rootDir>/client", "<rootDir>/test"],
  testMatch: [
    "**/__tests__/**/*.test.ts",
    "**/__tests__/**/*.test.tsx",
    "**/test/**/*.test.ts",
  ],
  setupFilesAfterEnv: ["<rootDir>/client/__tests__/setup.ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: {
          esModuleInterop: true,
          jsx: "react",
          allowJs: true,
          moduleResolution: "node",
        },
      },
    ],
  },
  transformIgnorePatterns: ["node_modules/(?!(aws-jwt-verify)/)"],
  collectCoverageFrom: [
    "client/**/*.{ts,tsx}",
    "!client/**/*.d.ts",
    "!client/__tests__/**",
  ],
};
