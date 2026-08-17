"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const state = $("state");
  const mobileMap = $("mobile-map");
  const mobilePause = $("mobile-pause");
  if (!state || !mobileMap || !mobilePause) return;

  const activeStates = new Set(["queued", "running", "paused", "cancelling", "mapping"]);
  const sync = () => {
    const current = state.textContent.trim().toLowerCase();
    const active = activeStates.has(current);
    mobileMap.disabled = active;
    mobilePause.disabled = !(current === "running" || current === "paused");
    mobilePause.textContent = current === "paused" ? "Resume" : "Pause";
    $("mobile-run").disabled = active;
    $("mobile-stop").disabled = !active;
  };

  mobileMap.addEventListener("click", () => $("map-btn")?.click());
  mobilePause.addEventListener("click", () => {
    const current = state.textContent.trim().toLowerCase();
    if (current === "paused") $("resume-btn")?.click();
    else $("pause-btn")?.click();
  });
  new MutationObserver(sync).observe(state, {childList: true, subtree: true, characterData: true});
  sync();
})();
