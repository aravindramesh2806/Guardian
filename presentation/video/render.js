// Renders intro.html to guardian-intro.mp4, frame by frame, with the narration mixed in.
// Needs: puppeteer-core, react, react-dom, react-icons (NODE_PATH), Google Chrome, and FFMPEG=<path to ffmpeg>.
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const fa = require("react-icons/fa");
const puppeteer = require("puppeteer-core");

const DIR = __dirname;
const FFMPEG = process.env.FFMPEG || "ffmpeg";
const FPS = 30;
// Scene lengths in seconds, sized to each narration clip (narration/s1..s7.wav, from narrate.py) plus breathing room.
const LENGTHS = [4.0, 11.5, 12.7, 13.6, 7.6, 9.3, 7.0];
const VOICE_DELAY = 0.4; // each clip starts this long after its scene

const STARTS = LENGTHS.reduce((a, l, i) => (a.push(i ? a[i - 1] + LENGTHS[i - 1] : 0), a), []);
const END = STARTS[STARTS.length - 1] + LENGTHS[LENGTHS.length - 1];

let html = fs.readFileSync(path.join(DIR, "intro.template.html"), "utf8")
  .replace("{{STARTS}}", JSON.stringify(STARTS.map((s) => +s.toFixed(2))))
  .replace("{{END}}", END.toFixed(2))
  .replace(/\{\{(Fa\w+)\}\}/g, (_, n) => ReactDOMServer.renderToStaticMarkup(React.createElement(fa[n])));
fs.writeFileSync(path.join(DIR, "intro.html"), html);

(async () => {
  const browser = await puppeteer.launch({ executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", headless: true, args: ["--hide-scrollbars"] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });
  await page.goto("file://" + path.join(DIR, "intro.html"));
  await page.evaluateHandle("document.fonts.ready");

  const silent = path.join(DIR, "silent.mp4");
  const ff = spawn(FFMPEG, ["-y", "-f", "image2pipe", "-framerate", String(FPS), "-c:v", "mjpeg", "-i", "-",
    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "medium", silent], { stdio: ["pipe", "ignore", "inherit"] });
  const frames = Math.round(END * FPS);
  for (let f = 0; f < frames; f++) {
    await page.evaluate((t) => window.renderAt(t), f / FPS);
    const buf = await page.screenshot({ type: "jpeg", quality: 92 });
    if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once("drain", r));
    if (f % 150 === 0) console.log(`frame ${f}/${frames}`);
  }
  ff.stdin.end();
  await new Promise((r) => ff.on("close", r));
  await browser.close();

  // Mix the narration clips, each delayed to its scene.
  const ins = [], filt = [];
  LENGTHS.forEach((_, i) => {
    ins.push("-i", path.join(DIR, "narration", `s${i + 1}.wav`));
    const ms = Math.round((STARTS[i] + VOICE_DELAY) * 1000);
    filt.push(`[${i + 1}:a]adelay=${ms}|${ms}[a${i}]`);
  });
  const mix = filt.join(";") + ";" + LENGTHS.map((_, i) => `[a${i}]`).join("") + `amix=inputs=${LENGTHS.length}:normalize=0,apad=whole_dur=${END.toFixed(2)}[aout]`;
  const out = path.join(DIR, "guardian-intro.mp4");
  await new Promise((res, rej) => spawn(FFMPEG, ["-y", "-i", silent, ...ins, "-filter_complex", mix, "-map", "0:v", "-map", "[aout]",
    "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-t", END.toFixed(2), "-movflags", "+faststart", out], { stdio: "inherit" })
    .on("close", (c) => (c ? rej(new Error("ffmpeg " + c)) : res())));
  fs.unlinkSync(silent);
  console.log("wrote", out, `(${END.toFixed(1)} s)`);
})();
