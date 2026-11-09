// Decrypts payload.bin (salt | iv | AES-GCM ciphertext + tag) with a key
// stretched from the password, then shows the prototype in a blob iframe.
const form = document.getElementById("form");
const input = document.getElementById("password");
const button = form.querySelector("button");
const errorEl = document.getElementById("error");
const gate = document.getElementById("gate");
const frame = document.getElementById("frame");
const { day, expires, iterations } = document.body.dataset;

const closed = () => expires && Date.now() >= Date.parse(expires);

if (closed()) {
  form.querySelector(".hint").textContent = "This prototype is closed.";
  input.disabled = true;
  button.disabled = true;
}

async function decrypt(password) {
  const response = await fetch(`./payload.bin?day=${day}`, { cache: "no-store" });
  if (!response.ok) throw new Error("missing");
  const bytes = new Uint8Array(await response.arrayBuffer());
  const salt = bytes.subarray(0, 16);
  const iv = bytes.subarray(16, 28);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: Number(iterations) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, bytes.subarray(28));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (closed()) {
    errorEl.textContent = "This prototype is closed.";
    return;
  }
  errorEl.textContent = "";
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    // Case and dashes don't matter.
    const html = await decrypt(input.value.toUpperCase().replace(/[^A-Z0-9]/g, ""));
    frame.src = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    gate.remove();
    frame.style.display = "block";
  } catch {
    errorEl.textContent = "That password didn't work. Check it and try again.";
    button.disabled = false;
    button.textContent = "Enter";
  }
});
