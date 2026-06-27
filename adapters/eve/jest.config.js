/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
    "^eve-policy$": "<rootDir>/../../../eve-policy/src/index.ts",
    "^eve-policy/rules$": "<rootDir>/../../../eve-policy/src/rules/index.ts",
    "^eve-policy/profiles$": "<rootDir>/../../../eve-policy/src/profiles/index.ts",
    "^eve-policy/audit$": "<rootDir>/../../../eve-policy/src/audit/index.ts",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: {
          module: "NodeNext",
          moduleResolution: "NodeNext",
          paths: {
            "eve-policy": ["../../../eve-policy/src/index.ts"],
            "eve-policy/rules": ["../../../eve-policy/src/rules/index.ts"],
            "eve-policy/profiles": ["../../../eve-policy/src/profiles/index.ts"],
            "eve-policy/audit": ["../../../eve-policy/src/audit/index.ts"],
          },
        },
      },
    ],
  },
  testMatch: ["**/test/**/*.test.ts"],
};
