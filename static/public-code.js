const button = document.getElementById("refresh-code");
const code = document.getElementById("code");
const error = document.getElementById("refresh-error");

button.addEventListener("click", async () => {
  button.disabled = true;
  error.hidden = true;

  try {
    const response = await fetch(button.dataset.url, {
      method: "POST",
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (!/^\d{4}$/.test(data.code)) throw new Error("Invalid code");
    code.textContent = data.code;
  } catch {
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
});
