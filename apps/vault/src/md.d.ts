// Markdown files import as their text (the Text module rule in wrangler.jsonc).
declare module "*.md" {
  const text: string
  export default text
}
