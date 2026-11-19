import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER } from "./shared.ts"

// Without a human: reads, and creating or updating customers, products
// and prices. Charges, payment intents, invoices, payouts, refunds,
// transfers and anything else need an approval; webhooks are refused.
export const stripe: Template = {
  id: "stripe",
  displayName: "Stripe secret key",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://dashboard.stripe.com/apikeys",
  binding: { hosts: ["api.stripe.com"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      // Customer writes need a human: changing a customer's email redirects
      // their receipts and invoices to whoever the agent names.
      { action: "allow", methods: ["POST"], paths: ["/v1/products", "/v1/products/*", "/v1/prices", "/v1/prices/*"], note: "catalogue records" },
      { action: "approve", methods: ["POST", "DELETE"], paths: ["/v1/payouts/**", "/v1/refunds/**", "/v1/transfers/**"], note: "moves money" },
      { action: "deny", paths: ["/v1/webhook_endpoints/**", "/v1/webhook_endpoints"], methods: ["POST", "DELETE"], note: "webhooks" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1/balance" },
  fields: { key: { label: "Secret key", pattern: "^(sk|rk)_(test|live)_" } },
  prefixes: ["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
}
