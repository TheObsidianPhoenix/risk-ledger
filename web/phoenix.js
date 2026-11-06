// Obsidian Phoenix Labs watermark: a faint phoenix outline behind the page that
// slowly rises, breathes its wings and sends embers along its feathers.
// The drawing is a fixed string from this file (no outside or user data), parsed as SVG.
"use strict";
(() => {
  const PHOENIX = '<svg xmlns="http://www.w3.org/2000/svg" class="phoenix-mark" aria-hidden="true" focusable="false" viewBox="0 0 400 420" fill="none" stroke-linecap="round" stroke-linejoin="round"> <defs> <linearGradient id="phoenix-fire" gradientUnits="userSpaceOnUse" x1="0" y1="40" x2="0" y2="400"> <stop offset="0" stop-color="#b69cff"/><stop offset=".55" stop-color="#ff7f6e"/><stop offset="1" stop-color="#ffc9a8"/> </linearGradient> </defs> <g stroke="url(#phoenix-fire)" stroke-width="2.4"> <path d="M200 150 C 196 132, 198 116, 210 106 C 220 98, 232 100, 238 108 L 252 112 L 238 118 C 234 126, 224 130, 216 134 C 210 140, 206 146, 204 156"/> <path d="M212 104 C 206 90, 196 82, 182 80 M218 101 C 216 86, 210 74, 198 66 M224 100 C 226 86, 224 74, 216 62"/> <circle cx="226" cy="110" r="2.2"/> <path d="M204 156 C 214 176, 216 200, 206 224 C 200 238, 196 238, 192 224 C 184 200, 188 174, 200 150"/> <g class="wing-l"> <path d="M194 176 C 160 150, 120 120, 92 76 C 80 58, 70 44, 52 34"/> <path d="M194 176 C 150 170, 104 150, 70 108 C 58 92, 46 84, 30 80"/> <path d="M194 182 C 146 188, 100 176, 62 144 C 50 134, 38 130, 22 130"/> <path d="M194 190 C 152 204, 112 204, 76 186 C 64 180, 52 180, 40 184"/> <path d="M92 76 C 100 96, 112 110, 130 122 M70 108 C 84 122, 102 132, 124 138 M62 144 C 80 154, 100 160, 124 160"/> </g> <g class="wing-r"> <path d="M210 176 C 244 150, 284 120, 312 76 C 324 58, 334 44, 352 34"/> <path d="M210 176 C 254 170, 300 150, 334 108 C 346 92, 358 84, 374 80"/> <path d="M210 182 C 258 188, 304 176, 342 144 C 354 134, 366 130, 382 130"/> <path d="M210 190 C 252 204, 292 204, 328 186 C 340 180, 352 180, 364 184"/> <path d="M312 76 C 304 96, 292 110, 274 122 M334 108 C 320 122, 302 132, 280 138 M342 144 C 324 154, 304 160, 280 160"/> </g> <g class="tail"> <path d="M198 232 C 192 280, 160 320, 120 340 C 100 350, 96 368, 110 374 C 122 378, 128 366, 120 360"/> <path d="M200 236 C 202 290, 196 340, 200 384 C 202 400, 214 404, 220 396 C 224 388, 216 380, 210 386"/> <path d="M202 232 C 210 280, 242 320, 282 340 C 302 350, 306 368, 292 374 C 280 378, 274 366, 282 360"/> <path d="M199 234 C 184 270, 170 296, 150 312 M201 234 C 216 270, 230 296, 250 312"/> </g> </g> </svg>';
  const doc = new DOMParser().parseFromString(PHOENIX, "image/svg+xml");
  const mark = document.importNode(doc.documentElement, true);
  // Embers: a copy of every feather stroke, drawn as a short bright dash that travels along it.
  // Each copy sits next to its feather so it moves with the wing.
  mark.querySelectorAll("g[class] path").forEach((p, i) => {
    const e = p.cloneNode();
    e.setAttribute("class", "ember");
    e.style.animationDelay = (-((i * 1.37) % 9)).toFixed(2) + "s";
    p.after(e);
  });
  const add = () => document.body.prepend(mark);
  if (document.body) add(); else document.addEventListener("DOMContentLoaded", add);
})();
