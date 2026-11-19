// Mehen lander: the nav coil draws once on load, the hero terminal types once, the copy button,
// and the example activity log adds an illustrative row while it is on screen. No scroll listeners, no frame loops.
(() => {
  "use strict";
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- The nav coil draws itself once ---------- */
  (function drawCoil() {
    const coil = document.getElementById("nav-coil");
    if (!coil || reduced || typeof coil.animate !== "function") return;
    coil.classList.add("nav-coil-draw");
    const draw = coil.animate([{ strokeDashoffset: 240 }, { strokeDashoffset: 0 }], { duration: 1400, easing: "cubic-bezier(0.4, 0, 0.2, 1)", delay: 120 });
    draw.onfinish = () => coil.classList.remove("nav-coil-draw");
  })();

  /* ---------- The hero terminal types once ---------- */
  (function typeTerminal() {
    const code = document.getElementById("hero-type");
    if (!code || reduced) return;
    // Hold the finished height while it types, so nothing below it moves.
    const pre = code.closest("pre") || code;
    pre.style.minHeight = `${pre.offsetHeight}px`;
    const lines = code.innerHTML.split("\n");
    code.innerHTML = "";
    const cursor = document.createElement("span");
    cursor.className = "cursor";
    const prompt = '<span class="p">$</span> ';
    let i = 0;
    function next() {
      if (i >= lines.length) { cursor.remove(); pre.style.minHeight = ""; return; }
      const line = lines[i++];
      if (line.startsWith(prompt)) {
        const text = line.slice(prompt.length);
        const typed = document.createElement("span");
        code.insertAdjacentHTML("beforeend", prompt);
        code.appendChild(typed);
        code.appendChild(cursor);
        let c = 0;
        const tick = () => {
          typed.textContent = text.slice(0, ++c);
          if (c < text.length) setTimeout(tick, 34);
          else { code.insertAdjacentText("beforeend", "\n"); setTimeout(next, 320); }
        };
        setTimeout(tick, 160);
      } else {
        cursor.remove();
        code.insertAdjacentHTML("beforeend", line + "\n");
        code.appendChild(cursor);
        setTimeout(next, line.includes('class="hold"') || line.includes("approved") ? 520 : 140);
      }
    }
    code.appendChild(cursor);
    setTimeout(next, 500);
  })();

  /* ---------- Copy button ---------- */
  const status = document.getElementById("copy-status");
  document.querySelectorAll(".copy").forEach((btn) => {
    const label = btn.querySelector("span");
    btn.addEventListener("click", async () => {
      // "Copied" only once the clipboard took the text; otherwise say so.
      let copied = true;
      try { await navigator.clipboard.writeText(btn.dataset.copy); } catch (_) { copied = false; }
      const said = copied ? "Copied" : "Could not copy. Select and copy the text instead.";
      if (copied) btn.classList.add("done");
      label.textContent = copied ? "Copied" : "Could not copy";
      if (status) status.textContent = said;
      setTimeout(() => { btn.classList.remove("done"); label.textContent = "Copy"; if (status) status.textContent = ""; }, copied ? 1600 : 4000);
    });
  });

  /* ---------- Live crossings log: wide screens only, only while in view ---------- */
  // On a phone the log is a tall stack of cards, and a row arriving at its top
  // would push the page under the reader's thumb, so it stays still there. On
  // wide screens its height is held, so nothing around it moves either.
  (function liveLog() {
    const log = document.getElementById("log");
    const wide = matchMedia("(min-width: 1024px)");
    if (!log || reduced || !wide.matches || !("IntersectionObserver" in window)) return;
    const pool = [
      ["claude-code@my-laptop", "openai-personal", "POST api.openai.com/v1/embeddings", "ok", "Allowed", ""],
      ["cursor@my-laptop", "github-ci", "GET api.github.com/repos/acme/app", "ok", "Allowed", ""],
      ["codex@build-box", "stripe-live", "POST api.stripe.com/v1/customers", "hold", "Held", "a write waits for a passkey"],
      ["agent/inbox", "gmail-personal", "gmail read", "ok", "Allowed", ""],
      ["cron/nightly-report", "openai-personal", "POST api.openai.com/v1/responses", "ok", "Allowed", ""],
      ["claude-code@my-laptop", "stripe-live", "DELETE api.stripe.com/v1/customers/cus_9x", "no", "Refused", "DELETE is outside the binding; only a human can change it"],
      ["cursor@my-laptop", "openai-personal", "POST api.openai.com/v1/responses", "ok", "Allowed", ""],
      ["codex@build-box", "openai-personal", "POST evil-proxy.example/v1/chat", "no", "Refused", "not a bound host; refused before anything was sent"],
    ];    const pad = (n) => String(n).padStart(2, "0");
    let i = 0, h = 23, m = 41, s = 7, timer = 0;
    function add() {
      s += 9 + Math.floor(Math.random() * 30);
      if (s >= 60) { s -= 60; m++; }
      if (m >= 60) { m -= 60; h = (h + 1) % 24; }
      const [agent, cred, dest, kind, label, note] = pool[i++ % pool.length];
      const row = document.createElement("li");
      row.className = "row new";
      row.innerHTML = `<time>${pad(h)}:${pad(m)}:${pad(s)}</time><span class="agent">${agent}<small>${cred}</small></span><span class="dest">${dest}</span><span class="d ${kind}">${label}</span>${note ? `<small class="note">${note}</small>` : ""}`;
      const head = log.querySelector(".row-head");
      log.insertBefore(row, head ? head.nextSibling : log.firstChild);
      let rows = log.querySelectorAll(".row:not(.row-head)");
      while (rows.length > 1 && (rows.length > 6 || log.scrollHeight > log.clientHeight)) {
        rows[rows.length - 1].remove();
        rows = log.querySelectorAll(".row:not(.row-head)");
      }
    }
    log.style.height = `${log.offsetHeight}px`;
    log.classList.add("pinned");
    const observer = new IntersectionObserver((entries) => {
      for (const e of entries) {
        clearInterval(timer);
        timer = 0;
        if (e.isIntersecting) timer = setInterval(add, 4200);
      }
    }, { threshold: 0.3 });
    observer.observe(log);
    wide.addEventListener("change", () => {
      if (wide.matches) return;
      observer.disconnect();
      clearInterval(timer);
      log.style.height = "";
      log.classList.remove("pinned");
    });
  })();
})();
