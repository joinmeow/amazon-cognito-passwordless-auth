const path = require("path");

module.exports = {
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:security/recommended-legacy",
  ],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  overrides: [getClientOverrides("client")],
  plugins: ["@typescript-eslint", "header", "import"],
  root: true,
};

function rules() {
  return {
    "@typescript-eslint/no-non-null-assertion": "off",
    "require-await": "off",
    "@typescript-eslint/require-await": "off",
    "header/header": ["error", path.join(__dirname, "header.js")],
    "restrict-template-expressions": "off",
    "@typescript-eslint/restrict-template-expressions": [
      "error",
      { allowNullish: true },
    ],
    "import/extensions": ["error", "ignorePackages"],
  };
}

function getClientOverrides(basedir) {
  return {
    env: {
      browser: true,
      es2021: true,
      node: true,
    },
    files: "client/**/*",
    parserOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      tsconfigRootDir: __dirname,
      project: ["client/tsconfig.json"],
    },
    extends: [
      "eslint:recommended",
      "plugin:security/recommended-legacy",
      "plugin:react/recommended",
      "plugin:react-hooks/recommended",
      "plugin:@typescript-eslint/recommended",
      "plugin:@typescript-eslint/recommended-requiring-type-checking",
    ],
    settings: {
      react: {
        version: "detect",
      },
    },
    rules: {
      ...rules(),
      "react/react-in-jsx-scope": "off",
      "no-restricted-globals": [
        "error",
        "window",
        "document",
        "history",
        "location",
        "crypto",
        "fetch",
      ],
    },
    plugins: ["react", "@typescript-eslint", "header", "import"],
  };
}
