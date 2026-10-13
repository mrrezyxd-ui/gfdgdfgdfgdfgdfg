(function() {
  const pad = (n) => String(n).padStart(2, '0');

  function updateCard(card) {
    const target = parseInt(card.dataset.target, 10);
    if (!target || isNaN(target)) return;
    const now = Math.floor(Date.now() / 1000);
    let remaining = target - now;
    const daysEl = card.querySelector('.days');
    const hoursEl = card.querySelector('.hours');
    const minutesEl = card.querySelector('.minutes');
    const secondsEl = card.querySelector('.seconds');
    if (remaining <= 0) {
      card.classList.add('expired');
      if (daysEl) daysEl.textContent = '00';
      if (hoursEl) hoursEl.textContent = '00';
      if (minutesEl) minutesEl.textContent = '00';
      if (secondsEl) secondsEl.textContent = '00';
      return;
    }
    const days = Math.floor(remaining / 86400); remaining -= days * 86400;
    const hours = Math.floor(remaining / 3600); remaining -= hours * 3600;
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining - minutes * 60;
    if (daysEl) daysEl.textContent = pad(days);
    if (hoursEl) hoursEl.textContent = pad(hours);
    if (minutesEl) minutesEl.textContent = pad(minutes);
    if (secondsEl) secondsEl.textContent = pad(seconds);
  }
  function tick() { document.querySelectorAll('[data-target]').forEach(updateCard); }
  setInterval(tick, 1000);
  tick();
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
})();

(function() {
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => el.style.opacity = '0', 5000);
    setTimeout(() => el.remove(), 5500);
  });
})();

(function() {
  document.querySelectorAll('form.confirm-delete, [data-confirm]').forEach(form => {
    form.addEventListener('submit', (e) => {
      const msg = form.dataset.confirm || 'Are you sure? This cannot be undone.';
      if (!confirm(msg)) e.preventDefault();
    });
  });
})();

(function() {
  const el = document.getElementById('current-datetime');
  if (!el) return;
  function update() {
    el.textContent = new Date().toLocaleString(undefined, {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  }
  update();
  setInterval(update, 1000);
})();