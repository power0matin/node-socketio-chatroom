/* public/assets/app.js
 * Works with:
 *  - <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
 *  - <script src="/socket.io/socket.io.js"></script>
 *  - DOM template in index.html inside #app
 */

(() => {
  "use strict";

  if (!window.Vue) {
    console.error("Vue global not found. Did you load vue.global.js?");
    return;
  }
  if (!window.io) {
    console.error(
      "Socket.IO client not found. Did you load /socket.io/socket.io.js?",
    );
    return;
  }

  const { createApp, ref, onMounted, nextTick, computed } = window.Vue;
  const socket = window.io();

  // lightweight notification sound (same as your old inline)
  const notifyAudio = new Audio(
    "data:audio/mp3;base64,//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
  );

  createApp({
    setup() {
      // ---- auth / core ----
      const isLoggedIn = ref(false);
      const user = ref({ username: "", role: "user" });
      const loginForm = ref({ username: "", password: "" });
      const error = ref("");
      const appName = ref(document.title || "Chatroom");

      const isConnected = ref(socket.connected);
      const isAuthBusy = ref(false);

      // ---- channels / views ----
      const channels = ref([]);
      const currentChannel = ref("");
      const isPrivateChat = ref(false);
      const isSavedView = ref(false);
      const displayChannelName = ref("");

      // messages
      const messages = ref([]);
      const msgContainer = ref(null);

      // composer
      const messageText = ref("");

      // sidebar / ui
      const showSidebar = ref(false);

      // create channel
      const showCreateChannelInput = ref(false);
      const newChannelName = ref("");

      // lightbox
      const lightboxImage = ref(null);

      // bans
      const showBanModal = ref(false);
      const bannedUsers = ref([]);

      // admin settings
      const showAdminSettings = ref(false);
      const adminSettings = ref({
        hideUserList: false,
        accessMode: "restricted",
      });

      // unread (channels + DM partner usernames)
      const unreadCounts = ref({});

      // search
      const searchResults = ref([]);
      const searchQuery = ref("");

      // online users
      const onlineUsers = ref([]);

      // reply
      const replyingTo = ref(null);

      // context menu (message/user)
      const contextMenu = ref({
        visible: false,
        x: 0,
        y: 0,
        target: null,
        type: null,
      });

      // swipe-to-reply
      const swipeId = ref(null);
      const swipeStartX = ref(0);
      const swipeOffset = ref(0);

      // audio record
      const isRecording = ref(false);
      let mediaRecorder = null;
      let audioChunks = [];

      // upload
      const fileInput = ref(null);
      const isUploading = ref(false);
      const uploadProgress = ref(0);

      // scroll down button
      const showScrollDown = ref(false);

      // access modal (admin)
      const showAccessModal = ref(false);
      const accessModalUser = ref("");
      const accessChannels = ref([]);
      const accessMap = ref({});
      const accessDeniedBanner = ref("");

      // server-provided settings/token
      const appSettings = ref({ maxFileSizeMB: 50, accessMode: "restricted" });
      const uploadToken = ref("");

      // ---- computed ----
      const canCreateChannel = computed(
        () => user.value.role === "admin" || user.value.role === "vip",
      );
      const canBan = computed(
        () => user.value.role === "admin" || user.value.role === "vip",
      );

      const sortedUsers = computed(() => {
        const roles = { admin: 3, vip: 2, user: 1 };
        return [...(onlineUsers.value || [])].sort(
          (a, b) => (roles[b.role] || 0) - (roles[a.role] || 0),
        );
      });

      const canSend = computed(() => {
        const t = (messageText.value || "").trim();
        if (!t) return false;
        if (!isConnected.value) return false;
        if (!currentChannel.value) return false;
        return true;
      });

      // ---- utils ----
      const playSound = () => {
        try {
          notifyAudio.currentTime = 0;
          notifyAudio.play().catch(() => {});
        } catch {}
      };

      const notify = (title, body) => {
        playSound();
        try {
          if (
            "Notification" in window &&
            Notification.permission === "granted"
          ) {
            new Notification(title, { body, icon: "/favicon.ico" });
          }
        } catch {}
      };

      const scrollToBottom = (force = false) => {
        nextTick(() => {
          const c =
            document.getElementById("messages-container") || msgContainer.value;
          if (!c) return;

          // force: always go bottom
          if (force) {
            c.scrollTop = c.scrollHeight;
            return;
          }

          // default: go bottom
          c.scrollTop = c.scrollHeight;
        });
      };

      const scrollToMessage = (id) => {
        if (!id) return;
        const el = document.getElementById("msg-" + id);
        if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
      };

      const safeLink = (u) => {
        try {
          const s = String(u || "").trim();
          if (!s) return "#";
          if (s.startsWith("/uploads/")) return s; // allow protected uploads
          if (s.startsWith("data:")) return "#"; // block for download
          return "#";
        } catch {
          return "#";
        }
      };

      const autoResize = (e) => {
        try {
          e.target.style.height = "auto";
          e.target.style.height = e.target.scrollHeight + "px";
        } catch {}
      };

      // ---- auth ----
      const login = () => {
        if (!loginForm.value.username || !loginForm.value.password) {
          error.value = "نام کاربری و رمز عبور الزامی است";
          return;
        }
        error.value = "";
        isAuthBusy.value = true;
        socket.emit("login", loginForm.value);

        try {
          if ("Notification" in window) Notification.requestPermission();
        } catch {}
      };

      const logout = () => {
        try {
          localStorage.removeItem("chat_user_name");
        } catch {}
        window.location.reload();
      };

      // ---- channels / views ----
      const joinChannel = (ch) => {
        if (!ch) return;
        isSavedView.value = false;
        isPrivateChat.value = false;
        accessDeniedBanner.value = "";

        socket.emit("join_channel", ch);
        showSidebar.value = false;

        unreadCounts.value[ch] = 0;
      };

      const startPrivateChat = (targetUsername) => {
        isSavedView.value = false;

        // reset view immediately
        currentChannel.value = "";
        messages.value = [];
        isPrivateChat.value = true;
        displayChannelName.value = targetUsername;
        showSidebar.value = false;
        searchResults.value = [];
        searchQuery.value = "";
        accessDeniedBanner.value = "";

        unreadCounts.value[targetUsername] = 0;

        socket.emit("join_private", targetUsername, (res) => {
          if (!res || !res.ok) {
            accessDeniedBanner.value =
              "خطا در شروع پیام خصوصی: " + (res?.error || "NO_ACK");
            return;
          }
          currentChannel.value = res.dmId;
        });
      };

      const openSavedView = () => {
        isSavedView.value = true;
        isPrivateChat.value = true;
        displayChannelName.value = "پیام‌های ذخیره‌شده";
        showSidebar.value = false;
        accessDeniedBanner.value = "";

        socket.emit("join_saved");
      };

      // ---- messaging ----
      const sendMessage = () => {
        if (!canSend.value) return;

        socket.emit("send_message", {
          text: messageText.value,
          type: "text",
          channel: currentChannel.value,
          conversationId: currentChannel.value,
          replyTo: replyingTo.value,
        });

        messageText.value = "";
        replyingTo.value = null;
        scrollToBottom(true);
      };

      const handleComposerKeydown = (e) => {
        if (e.key !== "Enter") return;
        if (e.shiftKey) return;
        e.preventDefault();
        if (!canSend.value) return;
        sendMessage();
      };

      // reply helpers
      const setReply = (msg) => {
        replyingTo.value = msg;
        nextTick(() => {
          try {
            document.querySelector("textarea")?.focus();
          } catch {}
        });
      };
      const cancelReply = () => {
        replyingTo.value = null;
      };

      // save message
      const saveThisMessage = (msg) => {
        if (!msg) return;
        socket.emit("save_message", {
          originalId: msg.id,
          from: msg.sender,
          channel: msg.channel || msg.conversationId,
          type: msg.type,
          text: msg.text,
          content: msg.content,
          fileName: msg.fileName,
          originalAt: msg.timestamp || null,
        });
      };

      const unsave = (id) => {
        if (!id) return;
        socket.emit("saved_delete", id);
      };

      // ---- upload ----
      const handleFileUpload = (e) => {
        const file = e?.target?.files?.[0];
        if (!file) return;

        const maxMB = Number(appSettings.value?.maxFileSizeMB || 50);
        if (file.size > maxMB * 1024 * 1024) {
          alert("حجم فایل بیشتر از حد مجاز است (" + maxMB + "MB)");
          e.target.value = "";
          return;
        }

        const formData = new FormData();
        formData.append("file", file);

        isUploading.value = true;
        uploadProgress.value = 0;

        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/upload", true);
        if (uploadToken.value)
          xhr.setRequestHeader("X-Upload-Token", uploadToken.value);

        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) {
            uploadProgress.value = Math.round(
              (event.loaded / event.total) * 100,
            );
          }
        };

        xhr.onload = () => {
          try {
            if (xhr.status === 200) {
              const res = JSON.parse(xhr.responseText);

              let type = "file";
              if (String(res.mimetype || "").startsWith("image/"))
                type = "image";
              else if (String(res.mimetype || "").startsWith("video/"))
                type = "video";
              else if (String(res.mimetype || "").startsWith("audio/"))
                type = "audio";

              const securedUrl = uploadToken.value
                ? res.url + "?t=" + encodeURIComponent(uploadToken.value)
                : res.url;

              socket.emit("send_message", {
                text: "",
                type,
                content: securedUrl,
                fileName: res.filename,
                channel: currentChannel.value,
                conversationId: currentChannel.value,
                replyTo: replyingTo.value,
              });

              replyingTo.value = null;
              scrollToBottom(true);
            } else {
              alert("Upload Failed: Server Error");
            }
          } catch (err) {
            console.error(err);
            alert("Upload Failed: Invalid response");
          } finally {
            isUploading.value = false;
            try {
              if (fileInput.value) fileInput.value.value = "";
            } catch {}
          }
        };

        xhr.onerror = () => {
          isUploading.value = false;
          alert("Upload Network Error");
          try {
            if (fileInput.value) fileInput.value.value = "";
          } catch {}
        };

        xhr.send(formData);
      };

      // ---- audio recording ----
      const toggleRecording = async () => {
        if (isRecording.value) {
          try {
            mediaRecorder?.stop();
          } catch {}
          isRecording.value = false;
          return;
        }

        try {
          const stream = await navigator.mediaDevices.getUserMedia({
            audio: true,
          });
          mediaRecorder = new MediaRecorder(stream);
          audioChunks = [];

          mediaRecorder.ondataavailable = (event) =>
            audioChunks.push(event.data);

          mediaRecorder.onstop = () => {
            try {
              const audioBlob = new Blob(audioChunks, { type: "audio/webm" });
              const reader = new FileReader();
              reader.readAsDataURL(audioBlob);
              reader.onloadend = () => {
                socket.emit("send_message", {
                  text: "",
                  type: "audio",
                  content: reader.result,
                  channel: currentChannel.value,
                  conversationId: currentChannel.value,
                  replyTo: replyingTo.value,
                });
                replyingTo.value = null;
              };
            } catch (e) {
              console.error(e);
            }
          };

          mediaRecorder.start();
          isRecording.value = true;
        } catch (e) {
          alert("Microphone access denied");
        }
      };

      // ---- admin actions ----
      const deleteMessage = (msgId) => {
        if (!msgId) return;
        if (confirm("آیا مطمئن هستید؟")) socket.emit("delete_message", msgId);
      };

      const toggleCreateChannel = () => {
        showCreateChannelInput.value = !showCreateChannelInput.value;
      };

      const createChannel = () => {
        if (!newChannelName.value) return;
        socket.emit("create_channel", newChannelName.value);
        newChannelName.value = "";
        showCreateChannelInput.value = false;
      };

      const deleteChannel = (ch) => {
        if (!ch) return;
        if (confirm("حذف کانال؟")) socket.emit("delete_channel", ch);
      };

      const banUser = (target) => {
        if (!target) return;
        if (confirm("بن کردن کاربر " + target + " و حذف پیام‌ها؟"))
          socket.emit("ban_user", target);
      };

      const unbanUser = (target) => {
        if (!target) return;
        socket.emit("unban_user", target);
      };

      const setRole = (target, role) => {
        if (!target || !role) return;
        socket.emit("set_role", { targetUsername: target, role });
      };

      const openBanList = () => {
        socket.emit("get_banned_users");
        showBanModal.value = true;
      };

      const saveAdminSettings = () => {
        socket.emit("update_admin_settings", adminSettings.value);
        showAdminSettings.value = false;
      };

      // ---- Access modal (admin) ----
      const openAccessModal = (targetUsername) => {
        accessModalUser.value = targetUsername;
        showAccessModal.value = true;
        accessChannels.value = [];
        accessMap.value = {};
        socket.emit("admin_get_user_access", targetUsername);
      };

      const refreshAccessModal = () => {
        if (!accessModalUser.value) return;
        socket.emit("admin_get_user_access", accessModalUser.value);
      };

      const toggleUserAccess = (channel, allow) => {
        if (!accessModalUser.value) return;
        socket.emit("admin_set_user_access", {
          targetUsername: accessModalUser.value,
          channel,
          allow,
        });
      };

      // ---- search ----
      const searchUser = () => {
        if (searchQuery.value.length > 2)
          socket.emit("search_user", searchQuery.value);
        else searchResults.value = [];
      };

      // ---- user click / context ----
      const handleUserClick = (u) => {
        if (!u || !u.username) return;
        if (u.username !== user.value.username) startPrivateChat(u.username);
      };

      const showContext = (e, msg) => {
        contextMenu.value = {
          visible: true,
          x: e.pageX,
          y: e.pageY,
          target: msg,
          type: "message",
        };
      };

      const showUserContext = (e, targetUsername) => {
        contextMenu.value = {
          visible: true,
          x: e.pageX,
          y: e.pageY,
          target: targetUsername,
          type: "user",
        };
      };

      // ---- swipe reply ----
      const touchStart = (e, msg) => {
        swipeStartX.value = e.touches[0].clientX;
        swipeId.value = msg.id;
        swipeOffset.value = 0;
      };

      const touchMove = (e) => {
        if (!swipeId.value) return;
        const diff = e.touches[0].clientX - swipeStartX.value;
        if (diff < 0 && diff > -100) swipeOffset.value = diff;
      };

      const touchEnd = () => {
        if (swipeOffset.value < -50) {
          const msg = messages.value.find((m) => m.id === swipeId.value);
          if (msg) setReply(msg);
        }
        swipeId.value = null;
        swipeOffset.value = 0;
      };

      const getSwipeStyle = (id) => {
        return swipeId.value === id
          ? { transform: `translateX(${swipeOffset.value}px)` }
          : {};
      };

      // ---- image lightbox ----
      const viewImage = (src) => {
        lightboxImage.value = src;
      };

      // ---- socket events ----
      socket.on("connect", () => {
        isConnected.value = true;
      });

      socket.on("disconnect", () => {
        isConnected.value = false;
      });

      socket.on("login_success", (data) => {
        isLoggedIn.value = true;
        user.value = { username: data.username, role: data.role };

        channels.value = Array.isArray(data.channels) ? data.channels : [];
        uploadToken.value = data.uploadToken || "";

        if (data.settings) {
          appSettings.value = data.settings;

          if (data.settings.appName) {
            appName.value = data.settings.appName;
            document.title = data.settings.appName;
          }

          if (typeof data.settings.hideUserList === "boolean")
            adminSettings.value.hideUserList = data.settings.hideUserList;
          if (typeof data.settings.accessMode === "string")
            adminSettings.value.accessMode = data.settings.accessMode;
        }

        try {
          localStorage.setItem("chat_user_name", data.username);
        } catch {}

        isAuthBusy.value = false;

        // if no channels
        if (channels.value.length === 0) {
          currentChannel.value = "";
          displayChannelName.value = "بدون دسترسی";
          messages.value = [];
        }
      });

      socket.on("login_error", (msg) => {
        error.value = msg;
        isAuthBusy.value = false;
      });

      socket.on("force_disconnect", (msg) => {
        alert(msg);
        window.location.reload();
      });

      socket.on("channel_joined", (data) => {
        currentChannel.value = data.name;

        const saved = !!(data && data.isSaved);
        isSavedView.value = saved;

        isPrivateChat.value = !!data.isPrivate;

        if (saved) {
          displayChannelName.value = "پیام‌های ذخیره‌شده";
          return;
        }

        if (data.isPrivate) {
          const parts = String(data.name || "").split("_pv_");
          displayChannelName.value =
            parts.find((u) => u !== user.value.username) || "Private";
        } else {
          displayChannelName.value = data.name;
        }
      });

      socket.on("history", (msgs) => {
        messages.value = Array.isArray(msgs) ? msgs : [];
        scrollToBottom(true);
      });

      socket.on("receive_message", (msg) => {
        if (!msg) return;

        if (msg.channel === currentChannel.value) {
          const c = document.getElementById("messages-container");
          const isNearBottom = c
            ? c.scrollTop + c.clientHeight >= c.scrollHeight - 150
            : true;

          messages.value.push(msg);

          if (msg.sender === user.value.username || isNearBottom)
            scrollToBottom();

          if (document.hidden && msg.sender !== user.value.username) {
            notify(
              `پیام جدید در ${displayChannelName.value}`,
              `${msg.sender}: ${msg.text || "مدیا"}`,
            );
          }
        } else {
          // Unread logic
          if (String(msg.channel || "").includes("_pv_")) {
            const parts = String(msg.channel).split("_pv_");
            const partner = parts.find((p) => p !== user.value.username);
            if (partner) {
              unreadCounts.value[partner] =
                (unreadCounts.value[partner] || 0) + 1;
              notify(`پیام خصوصی از ${partner}`, msg.text || "فایل ارسال شد");
            }
          } else {
            unreadCounts.value[msg.channel] =
              (unreadCounts.value[msg.channel] || 0) + 1;
          }
        }
      });

      socket.on("message_deleted", (data) => {
        if (data && data.channel === currentChannel.value) {
          messages.value = messages.value.filter((m) => m.id !== data.id);
        }
      });

      socket.on("bulk_delete_user", (targetUser) => {
        messages.value = messages.value.filter((m) => m.sender !== targetUser);
      });

      socket.on("user_list", (list) => {
        onlineUsers.value = Array.isArray(list) ? list : [];
      });

      // admin-only broadcast; per-user list is channels_list
      socket.on("update_channels", (_list) => {});

      socket.on("channels_list", (list) => {
        channels.value = Array.isArray(list) ? list : [];

        // if current channel revoked/deleted (only for public)
        if (
          currentChannel.value &&
          !isPrivateChat.value &&
          !isSavedView.value
        ) {
          if (!channels.value.includes(currentChannel.value)) {
            messages.value = [];
            currentChannel.value = "";
            displayChannelName.value = "بدون دسترسی";
          }
        }
      });

      socket.on("channel_deleted", (ch) => {
        if (currentChannel.value === ch) {
          messages.value = [];
          currentChannel.value = "";
          displayChannelName.value = "کانال حذف شد";
        }
      });

      socket.on("access_denied", (data) => {
        accessDeniedBanner.value = data?.message
          ? data.message
          : "دسترسی ندارید.";
      });

      socket.on("access_revoked", (data) => {
        accessDeniedBanner.value = data?.message
          ? data.message
          : "دسترسی شما برداشته شد.";
        if (currentChannel.value === data?.channel) {
          messages.value = [];
          currentChannel.value = "";
          displayChannelName.value = "بدون دسترسی";
        }
      });

      socket.on("banned_list", (list) => {
        bannedUsers.value = Array.isArray(list) ? list : [];
      });

      socket.on("action_success", (msg) => {
        try {
          alert(msg);
        } catch {}
      });

      socket.on("role_update", (newRole) => {
        user.value.role = newRole;
        alert("نقش شما تغییر کرد: " + newRole);
      });

      socket.on("admin_user_access", (payload) => {
        if (!payload) return;
        if (payload.username !== accessModalUser.value) return;
        accessChannels.value = Array.isArray(payload.channels)
          ? payload.channels
          : [];
        accessMap.value =
          payload.map && typeof payload.map === "object" ? payload.map : {};
      });

      // ---- lifecycle ----
      onMounted(() => {
        // restore username for login form
        try {
          const storedUser = localStorage.getItem("chat_user_name");
          if (storedUser) loginForm.value.username = storedUser;
        } catch {}

        // hide context menu on click anywhere
        document.addEventListener("click", () => {
          contextMenu.value.visible = false;
        });

        // notifications permission
        try {
          if (
            "Notification" in window &&
            Notification.permission !== "granted" &&
            Notification.permission !== "denied"
          ) {
            Notification.requestPermission();
          }
        } catch {}

        // scroll listener for showScrollDown
        const c = document.getElementById("messages-container");
        if (c) {
          c.addEventListener(
            "scroll",
            () => {
              const isNearBottom =
                c.scrollTop + c.clientHeight >= c.scrollHeight - 150;
              showScrollDown.value = !isNearBottom;
            },
            { passive: true },
          );
        }
      });

      // ---- expose to template ----
      return {
        // core
        isLoggedIn,
        user,
        loginForm,
        error,
        login,
        logout,

        // channels / views
        channels,
        currentChannel,
        joinChannel,
        displayChannelName,
        isPrivateChat,
        isSavedView,

        // messages
        messages,
        msgContainer,

        // composer
        messageText,
        sendMessage,
        canSend,
        handleComposerKeydown,
        autoResize,

        // upload
        handleFileUpload,
        fileInput,
        isUploading,
        uploadProgress,
        uploadToken,

        // users / search
        onlineUsers,
        sortedUsers,
        searchUser,
        searchQuery,
        searchResults,
        startPrivateChat,
        handleUserClick,

        // sidebar / channel create
        showSidebar,
        toggleCreateChannel,
        showCreateChannelInput,
        newChannelName,
        createChannel,
        deleteChannel,

        // reply
        replyingTo,
        setReply,
        cancelReply,

        // admin / moderation
        deleteMessage,
        canCreateChannel,
        canBan,
        banUser,
        unbanUser,
        setRole,
        showBanModal,
        openBanList,
        bannedUsers,

        // context menu
        contextMenu,
        showContext,
        showUserContext,
        saveThisMessage,

        // swipe reply
        swipeId,
        touchStart,
        touchMove,
        touchEnd,
        getSwipeStyle,

        // audio
        isRecording,
        toggleRecording,

        // lightbox
        viewImage,
        lightboxImage,

        // ui / misc
        unreadCounts,
        appName,
        showAdminSettings,
        adminSettings,
        saveAdminSettings,
        isConnected,
        isAuthBusy,
        showScrollDown,
        scrollToBottom,
        scrollToMessage,

        // saved
        openSavedView,
        unsave,

        // access UI
        showAccessModal,
        accessModalUser,
        accessChannels,
        accessMap,
        openAccessModal,
        toggleUserAccess,
        refreshAccessModal,
        accessDeniedBanner,

        // safe
        safeLink,
      };
    },
  }).mount("#app");
})();
