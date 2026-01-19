(() => {
  const storageKey = "haproxy-theme";
  const toggle = document.querySelector("[data-theme-toggle]");
  const applyTheme = (theme) => {
    document.body.classList.toggle("dark-mode", theme === "dark");
  };

  const savedTheme = localStorage.getItem(storageKey) || "light";
  applyTheme(savedTheme);

  if (toggle) {
    toggle.checked = savedTheme === "dark";
    toggle.addEventListener("change", () => {
      const theme = toggle.checked ? "dark" : "light";
      localStorage.setItem(storageKey, theme);
      applyTheme(theme);
    });
  }
})();
