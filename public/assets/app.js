// public/assets/app.js (client)
(() => {
  if (!window.Vue) {
    document.body.innerHTML =
      '<div style="padding:24px;font-family:sans-serif;color:#b91c1c">Vue CDN load failed</div>';
    return;
  }
  if (!window.io) {
    document.body.innerHTML =
      '<div style="padding:24px;font-family:sans-serif;color:#b91c1c">Socket.IO client load failed</div>';
    return;
  }

  const { createApp, ref } = window.Vue;

  createApp({
    setup() {
      const isConnected = ref(false);
      const error = ref("");

      const socket = window.io({ transports: ["websocket", "polling"] });

      socket.on("connect", () => {
        isConnected.value = true;
        error.value = "";
      });

      socket.on("disconnect", () => {
        isConnected.value = false;
      });

      socket.on("connect_error", (e) => {
        isConnected.value = false;
        error.value = e?.message || String(e);
      });

      return { isConnected, error };
    },
    template: `
      <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:Vazirmatn,sans-serif">
        <div style="padding:22px;border:1px solid #eee;border-radius:16px;min-width:320px;text-align:center">
          <div style="font-weight:800;margin-bottom:8px">Client OK ✅</div>
          <div>Socket: <b :style="{color:isConnected?'#16a34a':'#dc2626'}">{{ isConnected?'Connected':'Disconnected' }}</b></div>
          <div v-if="error" style="margin-top:10px;font-size:12px;color:#dc2626;word-break:break-word">{{ error }}</div>
        </div>
      </div>
    `,
  }).mount("#app");
})();
