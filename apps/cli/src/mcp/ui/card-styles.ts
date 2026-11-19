// The cards' one stylesheet, inlined into each document. Mehen's Papyrus
// and Midnight palettes (apps/vault/src/ui/client/app.css) are the fallbacks
// behind the host's own variables (SEP-1865 theming); color-scheme follows
// the host's theme (data-theme) or, without one, the system's. No fonts are
// loaded and nothing is fetched.
export const CARD_STYLES = `
:root{color-scheme:light dark;
--m-bg:var(--color-background-primary,light-dark(#fbf7ee,#18223a));
--m-bg2:var(--color-background-secondary,light-dark(#f3ead8,#0f1626));
--m-text:var(--color-text-primary,light-dark(#1c1915,#fbf7ee));
--m-muted:var(--color-text-secondary,light-dark(#5e5547,#b4bccd));
--m-border:var(--color-border-primary,light-dark(rgb(28 25 21/.14),rgb(251 247 238/.12)));
--m-accent:light-dark(#1f6f73,#6ccfc6);
--m-primary:light-dark(#c4461f,#f2a65a);
--m-primary-strong:light-dark(#b03d1a,#f6b878);
--m-on-primary:light-dark(#fbf7ee,#0f1626);
--m-ok:var(--color-text-success,light-dark(#266f44,#7fd29a));
--m-warn:var(--color-text-warning,light-dark(#8a5a12,#ecc45a));
--m-danger:var(--color-text-danger,light-dark(#ab2a22,#f08a6a));
--m-sans:var(--font-sans,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif);
--m-mono:var(--font-mono,ui-monospace,"SF Mono",Menlo,Consolas,monospace);
--m-radius:var(--border-radius-lg,14px);
--m-radius-sm:var(--border-radius-md,9px)}
:root[data-theme=light]{color-scheme:light}
:root[data-theme=dark]{color-scheme:dark}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;padding:0;background:transparent}
body{font:14px/1.45 var(--m-sans);color:var(--m-text);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
#card:empty{display:none}
.card{max-width:560px;margin:0;padding:14px 16px 12px;border:1px solid var(--m-border);border-radius:var(--m-radius);background:var(--m-bg);overflow-wrap:anywhere}
.head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.eyebrow{display:flex;align-items:center;gap:6px;margin:0 0 3px;font:600 11px/1.2 var(--m-sans);letter-spacing:.06em;text-transform:uppercase;color:var(--m-muted)}
.eyebrow::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--m-accent)}
h1{margin:0;font-size:15.5px;line-height:1.3;font-weight:650;letter-spacing:-.005em}
.what{margin:6px 0 0;color:var(--m-text)}
.note{margin:8px 0 0;font-size:12.5px;color:var(--m-muted)}
.badge{flex:none;display:inline-flex;align-items:center;gap:6px;padding:3px 9px 3px 8px;border-radius:999px;font:600 12px/1.4 var(--m-sans);white-space:nowrap;color:var(--tone);background:color-mix(in srgb,var(--tone) 13%,transparent);border:1px solid color-mix(in srgb,var(--tone) 22%,transparent)}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.badge[data-tone=waiting]{--tone:var(--m-primary)}
.badge[data-tone=waiting]::before{animation:m-pulse 2.4s ease-in-out infinite}
.badge[data-tone=ok]{--tone:var(--m-ok)}
.badge[data-tone=warn]{--tone:var(--m-warn)}
.badge[data-tone=danger]{--tone:var(--m-danger)}
.badge[data-tone=quiet]{--tone:var(--m-muted)}
@keyframes m-pulse{50%{opacity:.35}}
@media (prefers-reduced-motion:reduce){.badge::before{animation:none!important}}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:5px 14px;margin:12px 0 0;padding:10px 12px;border-radius:var(--m-radius-sm);background:var(--m-bg2);font-size:13px}
.facts dt{color:var(--m-muted)}
.facts dd{margin:0;min-width:0}
.value{font-family:var(--m-mono);font-weight:600;font-size:12.5px;letter-spacing:.02em}
.expired{color:var(--m-danger);font-weight:600}
.message{margin:10px 0 0;font-size:13px;color:var(--m-muted)}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:12px 0 0}
button{font:inherit;cursor:pointer}
.primary{appearance:none;border:0;border-radius:var(--m-radius-sm);padding:8px 14px;min-height:36px;background:var(--m-primary);color:var(--m-on-primary);font-weight:600;font-size:13.5px;display:inline-flex;align-items:center;gap:7px;box-shadow:0 1px 0 rgb(0 0 0/.06),0 6px 16px -8px color-mix(in srgb,var(--m-primary) 60%,transparent);transition:background-color .15s,transform .05s}
.primary:hover{background:var(--m-primary-strong)}
.primary:active{transform:translateY(1px)}
.primary svg{width:14px;height:14px}
.secondary{appearance:none;border:1px solid var(--m-border);border-radius:var(--m-radius-sm);padding:5px 11px;min-height:30px;background:var(--m-bg);color:var(--m-text);font-weight:600;font-size:12.5px;display:inline-flex;align-items:center;gap:6px}
.secondary:hover{border-color:color-mix(in srgb,var(--m-primary) 55%,var(--m-border));color:var(--m-primary)}
.secondary svg{width:12px;height:12px}
:focus-visible{outline:2px solid var(--m-accent);outline-offset:2px}
.url{display:block;width:100%;margin:0;padding:7px 9px;border:1px dashed var(--m-border);border-radius:var(--m-radius-sm);background:var(--m-bg2);font:12px/1.4 var(--m-mono);color:var(--m-text);user-select:all;-webkit-user-select:all;word-break:break-all}
.url-box{width:100%}
.url-label{margin:0 0 4px;font-size:12px;color:var(--m-muted)}
.live{margin:10px 0 0;font-size:12px;color:var(--m-warn)}
.footer{display:flex;gap:7px;align-items:flex-start;margin:12px 0 0;padding-top:10px;border-top:1px solid var(--m-border);font-size:12px;line-height:1.4;color:var(--m-muted)}
.footer svg{flex:none;width:13px;height:13px;margin-top:1px;color:var(--m-accent)}
.asks{list-style:none;margin:10px 0 0;padding:0;display:grid;gap:8px}
.ask{padding:10px 12px;border:1px solid var(--m-border);border-radius:var(--m-radius-sm);background:var(--m-bg2)}
.ask .head{align-items:center}
.ask h2{margin:0;font-size:13.5px;line-height:1.3;font-weight:650}
.ask .what{margin-top:3px;font-size:13px}
.ask .meta{margin:5px 0 0;font-size:12px;color:var(--m-muted)}
.ask .meta .value{font-size:11.5px;color:var(--m-text)}
.ask .badge{font-size:11.5px;padding:2px 8px 2px 7px}
.ask .actions{margin-top:8px}
.more{margin:8px 0 0;font-size:12.5px;color:var(--m-muted)}
.figures{display:grid;grid-template-columns:repeat(auto-fit,minmax(84px,1fr));gap:8px;margin:12px 0 0;padding:0;list-style:none}
.figure{padding:8px 10px;border-radius:var(--m-radius-sm);background:var(--m-bg2)}
.figure b{display:block;font-size:18px;line-height:1.2;font-weight:650;font-variant-numeric:tabular-nums}
.figure span{display:block;font-size:11.5px;color:var(--m-muted)}
.figure.lead b{color:var(--m-primary)}
h2.section{margin:14px 0 6px;font:600 11px/1.2 var(--m-sans);letter-spacing:.06em;text-transform:uppercase;color:var(--m-muted)}
.rows{list-style:none;margin:0;padding:0;border:1px solid var(--m-border);border-radius:var(--m-radius-sm);overflow:hidden}
.rows li{display:flex;align-items:baseline;justify-content:space-between;gap:10px;padding:6px 10px;font-size:12.5px}
.rows li+li{border-top:1px solid var(--m-border)}
.rows .path{min-width:0;font-family:var(--m-mono);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.rows .path bdi{direction:ltr;unicode-bidi:isolate}
.rows .side{flex:none;display:flex;gap:8px;align-items:baseline;color:var(--m-muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.home{padding:1px 7px;border-radius:999px;font-size:11px;font-weight:600;color:var(--m-accent);background:color-mix(in srgb,var(--m-accent) 12%,transparent)}
.lines{margin:0;padding-left:18px;font-size:12.5px}
.lines li+li{margin-top:3px}
.reason{color:var(--m-muted)}
pre.command{margin:0;padding:8px 10px;border-radius:var(--m-radius-sm);background:var(--m-bg2);border:1px solid var(--m-border);font:12px/1.5 var(--m-mono);white-space:pre-wrap;overflow-wrap:anywhere;user-select:all;-webkit-user-select:all}
@media (max-width:380px){.card{padding:12px 12px 10px}.head{flex-wrap:wrap}.facts{grid-template-columns:1fr;gap:1px 0}.facts dd+dt{margin-top:6px}}
`
