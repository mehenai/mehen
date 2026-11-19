// /search without JavaScript: the build writes the page shell with the
// template (search.html), and the Worker fills in the query and the results.
// Everything it adds goes through the escaping `html` template.

import { html } from "./html.ts"
import { MAX_QUERY_CHARS, type SearchHit } from "./search.ts"

// Where the shell takes the results, and the search box's value.
export const SEARCH_RESULTS_MARK = "<!--search-results-->"
export const SEARCH_QUERY_MARK = "{{query}}"

export const SEARCH_LIMIT = 20

function results(query: string, hits: readonly SearchHit[]): string {
  const shown = query.slice(0, MAX_QUERY_CHARS)
  if (shown.trim() === "") {
    return html`<h1 id="search">Search</h1><p class="question">Type a word or a code into the search box: a command, an error, a tool or a provider.</p>`.value
  }
  if (hits.length === 0) {
    return html`<h1 id="search">Search</h1><p class="question">No results for “${shown}”.</p><p>Try fewer words, or the exact name of a command or an error code.</p>`.value
  }
  return html`<h1 id="search">Search</h1><p class="question">${hits.length} result${hits.length === 1 ? "" : "s"} for “${shown}”.</p><ol class="results">${hits.map((hit) => html`<li><a href="${hit.u}"><strong>${hit.t}</strong> <span aria-hidden="true">›</span> ${hit.h}</a><p>${hit.snippet}</p></li>`)}</ol>`.value
}

// The shell with the query in the search box and the results in the page.
export function renderSearch(shell: string, query: string, hits: readonly SearchHit[]): string {
  const value = html`${query.slice(0, MAX_QUERY_CHARS)}`.value
  // The query first: escaped, it cannot contain the results mark.
  return shell.replaceAll(SEARCH_QUERY_MARK, () => value).replace(SEARCH_RESULTS_MARK, () => results(query, hits))
}
