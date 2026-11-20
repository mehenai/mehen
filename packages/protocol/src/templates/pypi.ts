import type { Template } from "../templates.ts"

// A PyPI API token, for uploading releases. PyPI takes it as HTTP Basic
// credentials with the username "__token__", at its upload endpoint only;
// reads need no token and are not bound, and TestPyPI tokens are another
// index's. Every upload needs an approval: a release is public and
// permanent.
// https://pypi.org/help/#apitoken
export const pypi: Template = {
  id: "pypi",
  displayName: "PyPI API token",
  kind: "basic-auth",
  category: "code",
  docsUrl: "https://pypi.org/manage/account/token/",
  binding: { hosts: ["upload.pypi.org"], paths: ["/legacy/"], methods: ["POST"] },
  injection: { in: "basic", username: "username", password: "password" },
  policy: {
    default: "approve",
    rules: [{ action: "approve", methods: ["POST"], paths: ["/legacy/"], note: "publishes a release" }],
  },
  ceiling: "placeholder",
  defaultEnvVar: "TWINE_PASSWORD",
  fields: {
    username: { label: "Username", hint: "Always __token__ for an API token." },
    password: { label: "API token", pattern: "^pypi-" },
  },
  prefixes: ["pypi-"],
  setup: {
    title: "On PyPI",
    steps: [
      { title: "Open API tokens", body: "Account settings, then API tokens.", docs: true },
      { title: "Set the username", body: "Type __token__, which PyPI expects with every API token.", field: "username" },
      { title: "Create a token scoped to one project", body: "Scope it to the project the agent releases, not the whole account.", field: "password" },
    ],
  },
}
