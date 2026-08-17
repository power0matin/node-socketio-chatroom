/* public/assets/app.js */
(() => {
  'use strict';

  if (!window.Vue || !window.io) {
    console.error('Required self-hosted frontend runtime is unavailable.');
    return;
  }

  const { createApp, ref, computed, nextTick, onMounted, onBeforeUnmount } = window.Vue;
  const socket = window.io();
  const SESSION_KEY = 'chat_session_token';
  const USER_KEY = 'chat_user_name';

  createApp({
    setup() {
      const isLoggedIn = ref(false);
      const user = ref({ username: '', role: 'user' });
      const loginForm = ref({ username: '', password: '' });
      const error = ref('');
      const appName = ref(document.title || 'Chatroom');
      const isConnected = ref(socket.connected);
      const isAuthBusy = ref(false);
      const sessionToken = ref('');
      const channels = ref([]);
      const currentChannel = ref('');
      const isPrivateChat = ref(false);
      const isSavedView = ref(false);
      const displayChannelName = ref('');
      const messages = ref([]);
      const msgContainer = ref(null);
      const messageText = ref('');
      const showSidebar = ref(false);
      const showCreateChannelInput = ref(false);
      const newChannelName = ref('');
      const lightboxImage = ref(null);
      const showBanModal = ref(false);
      const bannedUsers = ref([]);
      const showAdminSettings = ref(false);
      const adminSettings = ref({ hideUserList: false, accessMode: 'restricted' });
      const unreadCounts = ref({});
      const searchResults = ref([]);
      const searchQuery = ref('');
      const onlineUsers = ref([]);
      const replyingTo = ref(null);
      const contextMenu = ref({ visible: false, x: 0, y: 0, target: null, type: null });
      const swipeId = ref(null);
      const swipeStartX = ref(0);
      const swipeOffset = ref(0);
      const isRecording = ref(false);
      const fileInput = ref(null);
      const isUploading = ref(false);
      const uploadProgress = ref(0);
      const showScrollDown = ref(false);
      const showAccessModal = ref(false);
      const accessModalUser = ref('');
      const accessChannels = ref([]);
      const accessMap = ref({});
      const accessDeniedBanner = ref('');
      const appSettings = ref({ maxFileSizeMB: 50, accessMode: 'restricted' });

      let mediaRecorder = null;
      let mediaStream = null;
      let audioChunks = [];
      let resumeInFlight = false;
      let longPressTimer = null;
      let longPressStart = null;
      let mutationObserver = null;

      const canCreateChannel = computed(() => user.value.role === 'admin' || user.value.role === 'vip');
      const canBan = computed(() => user.value.role === 'admin' || user.value.role === 'vip');
      const sortedUsers = computed(() => {
        const rank = { admin: 3, vip: 2, user: 1 };
        return [...onlineUsers.value].sort((a, b) => (rank[b.role] || 0) - (rank[a.role] || 0));
      });
      const canSend = computed(() => Boolean(
        (messageText.value || '').trim() && isConnected.value && isLoggedIn.value && currentChannel.value,
      ));

      function persistSession(token, username) {
        sessionToken.value = token || '';
        try {
          if (token) localStorage.setItem(SESSION_KEY, token);
          else localStorage.removeItem(SESSION_KEY);
          if (username) localStorage.setItem(USER_KEY, username);
        } catch {}
      }

      function clearSession() {
        sessionToken.value = '';
        try { localStorage.removeItem(SESSION_KEY); } catch {}
      }

      function scrollToBottom(force = false) {
        nextTick(() => {
          const container = document.getElementById('messages-container') || msgContainer.value;
          if (!container) return;
          const nearBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 150;
          if (force || nearBottom) container.scrollTop = container.scrollHeight;
        });
      }

      function scrollToMessage(id) {
        document.getElementById(`msg-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }

      function safeLink(value) {
        try {
          const url = new URL(String(value || ''), location.origin);
          return url.origin === location.origin && /^\/uploads\/[0-9a-f]{36}$/i.test(url.pathname) && url.searchParams.has('d')
            ? `${url.pathname}${url.search}` : '#';
        } catch { return '#'; }
      }

      function playNotification(title, body) {
        try {
          if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body, icon: '/favicon.svg' });
          }
        } catch {}
      }

      function autoResize(event) {
        const el = event?.target;
        if (!el) return;
        el.style.height = 'auto';
        el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
      }

      function applyAuth(data, resumed = false) {
        if (!data?.username || !data?.sessionToken) return;
        isLoggedIn.value = true;
        user.value = { username: data.username, role: data.role || 'user' };
        channels.value = Array.isArray(data.channels) ? data.channels : [];
        persistSession(data.sessionToken, data.username);
        loginForm.value.username = data.username;
        loginForm.value.password = '';
        error.value = '';
        isAuthBusy.value = false;
        if (data.settings) {
          appSettings.value = data.settings;
          if (data.settings.appName) {
            appName.value = data.settings.appName;
            document.title = data.settings.appName;
          }
          if (typeof data.settings.hideUserList === 'boolean') adminSettings.value.hideUserList = data.settings.hideUserList;
          if (typeof data.settings.accessMode === 'string') adminSettings.value.accessMode = data.settings.accessMode;
        }
        if (resumed) rejoinCurrentView();
        else if (!currentChannel.value && !channels.value.length) displayChannelName.value = 'بدون دسترسی';
      }

      function attemptResume() {
        if (!socket.connected || !sessionToken.value || resumeInFlight) return;
        resumeInFlight = true;
        socket.emit('resume_session', sessionToken.value, (result) => {
          resumeInFlight = false;
          if (!result?.ok) {
            clearSession();
            if (!isLoggedIn.value) isAuthBusy.value = false;
          }
        });
      }

      function rejoinCurrentView() {
        if (!isLoggedIn.value || !currentChannel.value) return;
        if (isSavedView.value) return socket.emit('join_saved');
        if (isPrivateChat.value) {
          const target = String(currentChannel.value).split('_pv_').find((name) => name !== user.value.username);
          if (target) socket.emit('join_private', target);
          return;
        }
        socket.emit('join_channel', currentChannel.value);
      }

      function login() {
        if (!loginForm.value.username || !loginForm.value.password) {
          error.value = 'نام کاربری و رمز عبور الزامی است';
          return;
        }
        error.value = '';
        isAuthBusy.value = true;
        socket.emit('login', { username: loginForm.value.username, password: loginForm.value.password });
        try {
          if ('Notification' in window && Notification.permission === 'default') void Notification.requestPermission();
        } catch {}
      }

      function logout() {
        const finish = () => {
          clearSession();
          try { localStorage.removeItem(USER_KEY); } catch {}
          location.reload();
        };
        if (!socket.connected || !isLoggedIn.value) return finish();
        socket.emit('logout', () => finish());
        setTimeout(finish, 1500);
      }

      function joinChannel(channel) {
        if (!channel) return;
        isSavedView.value = false;
        isPrivateChat.value = false;
        accessDeniedBanner.value = '';
        socket.emit('join_channel', channel);
        showSidebar.value = false;
        unreadCounts.value[channel] = 0;
      }

      function startPrivateChat(targetUsername) {
        if (!targetUsername || targetUsername === user.value.username) return;
        isSavedView.value = false;
        isPrivateChat.value = true;
        currentChannel.value = '';
        messages.value = [];
        displayChannelName.value = targetUsername;
        showSidebar.value = false;
        searchResults.value = [];
        searchQuery.value = '';
        accessDeniedBanner.value = '';
        unreadCounts.value[targetUsername] = 0;
        socket.emit('join_private', targetUsername, (result) => {
          if (!result?.ok) {
            accessDeniedBanner.value = `خطا در شروع پیام خصوصی: ${result?.error || 'NO_ACK'}`;
            isPrivateChat.value = false;
            return;
          }
          currentChannel.value = result.dmId;
        });
      }

      function openSavedView() {
        isSavedView.value = true;
        isPrivateChat.value = true;
        displayChannelName.value = 'پیام‌های ذخیره‌شده';
        showSidebar.value = false;
        accessDeniedBanner.value = '';
        socket.emit('join_saved');
      }

      function sendMessage() {
        if (!canSend.value) return;
        socket.emit('send_message', {
          text: messageText.value,
          type: 'text',
          conversationId: currentChannel.value,
          replyTo: replyingTo.value?.id || null,
        });
        messageText.value = '';
        replyingTo.value = null;
        scrollToBottom(true);
      }

      function handleComposerKeydown(event) {
        if (event.key !== 'Enter' || event.shiftKey) return;
        event.preventDefault();
        sendMessage();
      }

      function setReply(message) { replyingTo.value = message || null; }
      function cancelReply() { replyingTo.value = null; }
      function saveThisMessage(message) {
        if (message?.id) socket.emit('save_message', { originalId: message.id });
      }
      function unsave(id) { if (id) socket.emit('saved_delete', id); }

      function uploadFile(file, onProgress) {
        return new Promise((resolve, reject) => {
          if (!sessionToken.value) return reject(new Error('AUTH_REQUIRED'));
          const form = new FormData();
          form.append('file', file);
          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/upload', true);
          xhr.setRequestHeader('X-Auth-Token', sessionToken.value);
          xhr.upload.onprogress = (event) => {
            if (event.lengthComputable && onProgress) onProgress(Math.round((event.loaded / event.total) * 100));
          };
          xhr.onload = () => {
            let response;
            try { response = JSON.parse(xhr.responseText || '{}'); } catch { response = {}; }
            if (xhr.status === 200 && response.url) resolve(response);
            else reject(new Error(response.error || `UPLOAD_${xhr.status}`));
          };
          xhr.onerror = () => reject(new Error('UPLOAD_NETWORK_ERROR'));
          xhr.onabort = () => reject(new Error('UPLOAD_ABORTED'));
          xhr.send(form);
        });
      }

      async function sendUploadedFile(file, forcedType = null) {
        const maxMB = Number(appSettings.value?.maxFileSizeMB || 50);
        if (file.size > maxMB * 1024 * 1024) throw new Error(`حجم فایل بیشتر از ${maxMB}MB است.`);
        const response = await uploadFile(file, (value) => { uploadProgress.value = value; });
        let type = forcedType || 'file';
        if (!forcedType) {
          if (String(response.mimetype).startsWith('image/')) type = 'image';
          else if (String(response.mimetype).startsWith('video/')) type = 'video';
          else if (String(response.mimetype).startsWith('audio/')) type = 'audio';
        }
        socket.emit('send_message', {
          text: '', type, content: response.url, conversationId: currentChannel.value,
          replyTo: replyingTo.value?.id || null,
        });
        replyingTo.value = null;
      }

      async function handleFileUpload(event) {
        const file = event?.target?.files?.[0];
        if (!file) return;
        isUploading.value = true;
        uploadProgress.value = 0;
        try { await sendUploadedFile(file); }
        catch (uploadError) { alert(uploadError.message || 'Upload Failed'); }
        finally {
          isUploading.value = false;
          uploadProgress.value = 0;
          if (event?.target) event.target.value = '';
        }
      }

      function stopMediaTracks() {
        if (mediaStream) {
          for (const track of mediaStream.getTracks()) track.stop();
        }
        mediaStream = null;
      }

      async function toggleRecording() {
        if (isRecording.value) {
          try { mediaRecorder?.stop(); } catch { stopMediaTracks(); }
          isRecording.value = false;
          return;
        }
        if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
          alert('ضبط صدا در این مرورگر پشتیبانی نمی‌شود.');
          return;
        }
        try {
          mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
          const mimeType = MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm' : '';
          mediaRecorder = mimeType ? new MediaRecorder(mediaStream, { mimeType }) : new MediaRecorder(mediaStream);
          audioChunks = [];
          mediaRecorder.ondataavailable = (event) => { if (event.data?.size) audioChunks.push(event.data); };
          mediaRecorder.onerror = () => {
            isRecording.value = false;
            stopMediaTracks();
            alert('خطا در ضبط صدا.');
          };
          mediaRecorder.onstop = async () => {
            isRecording.value = false;
            const type = mediaRecorder?.mimeType || 'audio/webm';
            stopMediaTracks();
            try {
              const blob = new Blob(audioChunks, { type });
              if (!blob.size) return;
              const extension = type.includes('mpeg') ? 'mp3' : 'webm';
              const file = new File([blob], `recording.${extension}`, { type });
              isUploading.value = true;
              await sendUploadedFile(file, 'audio');
            } catch (recordError) {
              alert(recordError.message || 'ارسال صدا ناموفق بود.');
            } finally {
              isUploading.value = false;
              uploadProgress.value = 0;
              audioChunks = [];
              mediaRecorder = null;
            }
          };
          mediaRecorder.start();
          isRecording.value = true;
        } catch {
          isRecording.value = false;
          stopMediaTracks();
          alert('دسترسی میکروفون داده نشد.');
        }
      }

      function deleteMessage(id) { if (id && confirm('آیا مطمئن هستید؟')) socket.emit('delete_message', id); }
      function toggleCreateChannel() { showCreateChannelInput.value = !showCreateChannelInput.value; }
      function createChannel() {
        if (!newChannelName.value.trim()) return;
        socket.emit('create_channel', newChannelName.value);
        newChannelName.value = '';
        showCreateChannelInput.value = false;
      }
      function deleteChannel(channel) { if (channel && confirm('حذف کانال؟')) socket.emit('delete_channel', channel); }
      function banUser(target) { if (target && confirm(`بن کردن کاربر ${target} و حذف پیام‌ها؟`)) socket.emit('ban_user', target); }
      function unbanUser(target) { if (target) socket.emit('unban_user', target); }
      function setRole(target, role) { if (target && role) socket.emit('set_role', { targetUsername: target, role }); }
      function openBanList() { socket.emit('get_banned_users'); showBanModal.value = true; }
      function saveAdminSettings() { socket.emit('update_admin_settings', adminSettings.value); showAdminSettings.value = false; }
      function openAccessModal(target) {
        accessModalUser.value = target;
        showAccessModal.value = true;
        accessChannels.value = [];
        accessMap.value = {};
        socket.emit('admin_get_user_access', target);
      }
      function refreshAccessModal() { if (accessModalUser.value) socket.emit('admin_get_user_access', accessModalUser.value); }
      function toggleUserAccess(channel, allow) {
        if (accessModalUser.value) socket.emit('admin_set_user_access', { targetUsername: accessModalUser.value, channel, allow });
      }
      function searchUser() {
        if (searchQuery.value.trim().length >= 3) socket.emit('search_user', searchQuery.value);
        else searchResults.value = [];
      }
      function handleUserClick(item) { if (item?.username && item.username !== user.value.username) startPrivateChat(item.username); }
      function showContext(event, message) {
        contextMenu.value = { visible: true, x: event.pageX, y: event.pageY, target: message, type: 'message' };
      }
      function showUserContext(event, target) {
        contextMenu.value = { visible: true, x: event.pageX, y: event.pageY, target, type: 'user' };
      }

      function lpMove(event) {
        if (!longPressStart || !event?.touches?.[0]) return;
        const touch = event.touches[0];
        if (Math.abs(touch.clientX - longPressStart.x) > 12 || Math.abs(touch.clientY - longPressStart.y) > 12) lpEnd();
      }
      function lpEnd() {
        if (longPressTimer) clearTimeout(longPressTimer);
        longPressTimer = null;
        longPressStart = null;
      }
      function beginLongPress(event, callback) {
        lpEnd();
        const touch = event?.touches?.[0];
        if (!touch) return;
        longPressStart = { x: touch.clientX, y: touch.clientY };
        longPressTimer = setTimeout(() => { callback(touch); lpEnd(); }, 550);
      }
      function lpStartUser(event, target) {
        beginLongPress(event, (touch) => showUserContext({ pageX: touch.clientX, pageY: touch.clientY }, target));
      }
      function lpStartMessage(event, message) {
        beginLongPress(event, (touch) => showContext({ pageX: touch.clientX, pageY: touch.clientY }, message));
      }

      function touchStart(event, message) {
        swipeStartX.value = event.touches[0].clientX;
        swipeId.value = message.id;
        swipeOffset.value = 0;
      }
      function touchMove(event) {
        if (!swipeId.value) return;
        const delta = event.touches[0].clientX - swipeStartX.value;
        if (delta < 0 && delta > -100) swipeOffset.value = delta;
      }
      function touchEnd() {
        if (swipeOffset.value < -50) {
          const message = messages.value.find((entry) => entry.id === swipeId.value);
          if (message) setReply(message);
        }
        swipeId.value = null;
        swipeOffset.value = 0;
      }
      function getSwipeStyle(id) { return swipeId.value === id ? { transform: `translateX(${swipeOffset.value}px)` } : {}; }
      function viewImage(src) { lightboxImage.value = src; }
      function onComposerFocus() { setTimeout(() => scrollToBottom(false), 100); }
      function onComposerBlur() {}

      socket.on('connect', () => {
        isConnected.value = true;
        if (sessionToken.value) attemptResume();
      });
      socket.on('disconnect', () => { isConnected.value = false; });
      socket.on('connect_error', (connectionError) => {
        if (!isLoggedIn.value) error.value = `خطا در اتصال: ${connectionError.message}`;
        isAuthBusy.value = false;
      });
      socket.on('login_success', (data) => applyAuth(data, false));
      socket.on('session_resumed', (data) => { resumeInFlight = false; applyAuth(data, true); });
      socket.on('session_invalid', () => {
        resumeInFlight = false;
        clearSession();
        if (isLoggedIn.value) {
          isLoggedIn.value = false;
          messages.value = [];
          currentChannel.value = '';
          error.value = 'نشست شما منقضی یا لغو شده است. دوباره وارد شوید.';
        }
      });
      socket.on('session_refresh', (data) => {
        if (data?.sessionToken) persistSession(data.sessionToken, user.value.username);
        if (data?.role) user.value.role = data.role;
      });
      socket.on('login_error', (message) => { error.value = message; isAuthBusy.value = false; });
      socket.on('auth_required', () => { clearSession(); isLoggedIn.value = false; error.value = 'ابتدا وارد شوید.'; });
      socket.on('force_disconnect', (message) => { clearSession(); alert(message); location.reload(); });
      socket.on('channel_joined', (data) => {
        currentChannel.value = data.name;
        isSavedView.value = Boolean(data.isSaved);
        isPrivateChat.value = Boolean(data.isPrivate);
        if (data.isSaved) displayChannelName.value = 'پیام‌های ذخیره‌شده';
        else if (data.isPrivate) displayChannelName.value = String(data.name).split('_pv_').find((name) => name !== user.value.username) || 'Private';
        else displayChannelName.value = data.name;
      });
      socket.on('history', (items) => { messages.value = Array.isArray(items) ? items : []; scrollToBottom(true); });
      socket.on('receive_message', (message) => {
        if (!message) return;
        if (message.channel === currentChannel.value) {
          if (!messages.value.some((item) => item.id === message.id)) messages.value.push(message);
          if (message.sender === user.value.username) scrollToBottom();
          else if (document.hidden) playNotification(`پیام جدید در ${displayChannelName.value}`, `${message.sender}: ${message.text || 'مدیا'}`);
        } else if (String(message.channel || '').includes('_pv_')) {
          const partner = String(message.channel).split('_pv_').find((name) => name !== user.value.username);
          if (partner) {
            unreadCounts.value[partner] = (unreadCounts.value[partner] || 0) + 1;
            playNotification(`پیام خصوصی از ${partner}`, message.text || 'فایل ارسال شد');
          }
        } else if (!String(message.channel || '').startsWith('__saved__')) {
          unreadCounts.value[message.channel] = (unreadCounts.value[message.channel] || 0) + 1;
        }
      });
      socket.on('message_deleted', (data) => {
        if (data?.channel === currentChannel.value) messages.value = messages.value.filter((item) => item.id !== data.id);
      });
      socket.on('bulk_delete_user', (target) => { messages.value = messages.value.filter((item) => item.sender !== target); });
      socket.on('user_list', (list) => { onlineUsers.value = Array.isArray(list) ? list : []; });
      socket.on('update_channels', () => {});
      socket.on('channels_list', (list) => {
        channels.value = Array.isArray(list) ? list : [];
        if (currentChannel.value && !isPrivateChat.value && !isSavedView.value && !channels.value.includes(currentChannel.value)) {
          messages.value = [];
          currentChannel.value = '';
          displayChannelName.value = 'بدون دسترسی';
        }
      });
      socket.on('channel_deleted', (channel) => {
        if (currentChannel.value === channel) {
          messages.value = [];
          currentChannel.value = '';
          displayChannelName.value = 'کانال حذف شد';
        }
      });
      socket.on('access_denied', (data) => { accessDeniedBanner.value = data?.message || 'دسترسی ندارید.'; });
      socket.on('access_revoked', (data) => {
        accessDeniedBanner.value = data?.message || 'دسترسی شما برداشته شد.';
        if (currentChannel.value === data?.channel) {
          messages.value = [];
          currentChannel.value = '';
          displayChannelName.value = 'بدون دسترسی';
        }
      });
      socket.on('banned_list', (list) => { bannedUsers.value = Array.isArray(list) ? list : []; });
      socket.on('action_success', (message) => { if (message) alert(message); });
      socket.on('role_update', (role) => { user.value.role = role; });
      socket.on('admin_user_access', (payload) => {
        if (!payload || payload.username !== accessModalUser.value) return;
        accessChannels.value = Array.isArray(payload.channels) ? payload.channels : [];
        accessMap.value = payload.map && typeof payload.map === 'object' ? payload.map : {};
      });
      socket.on('error', (message) => { if (typeof message === 'string') accessDeniedBanner.value = message; });

      function attachScrollListener() {
        const container = document.getElementById('messages-container');
        if (!container || container.dataset.scrollBound) return;
        container.dataset.scrollBound = '1';
        container.addEventListener('scroll', () => {
          showScrollDown.value = container.scrollTop + container.clientHeight < container.scrollHeight - 150;
        }, { passive: true });
      }

      onMounted(() => {
        try {
          loginForm.value.username = localStorage.getItem(USER_KEY) || '';
          sessionToken.value = localStorage.getItem(SESSION_KEY) || '';
        } catch {}
        if (socket.connected && sessionToken.value) attemptResume();
        document.addEventListener('click', lpEnd);
        attachScrollListener();
        mutationObserver = new MutationObserver(attachScrollListener);
        mutationObserver.observe(document.body, { childList: true, subtree: true });
      });

      onBeforeUnmount(() => {
        lpEnd();
        stopMediaTracks();
        mutationObserver?.disconnect();
        document.removeEventListener('click', lpEnd);
      });

      return {
        isLoggedIn, user, loginForm, error, login, logout,
        channels, currentChannel, joinChannel, displayChannelName, isPrivateChat, isSavedView,
        messages, msgContainer, messageText, sendMessage, canSend, handleComposerKeydown, autoResize,
        handleFileUpload, fileInput, isUploading, uploadProgress,
        onlineUsers, sortedUsers, searchUser, searchQuery, searchResults, startPrivateChat, handleUserClick,
        showSidebar, toggleCreateChannel, showCreateChannelInput, newChannelName, createChannel, deleteChannel,
        replyingTo, setReply, cancelReply,
        deleteMessage, canCreateChannel, canBan, banUser, unbanUser, setRole, showBanModal, openBanList, bannedUsers,
        contextMenu, showContext, showUserContext, saveThisMessage,
        swipeId, swipeOffset, touchStart, touchMove, touchEnd, getSwipeStyle,
        isRecording, toggleRecording, viewImage, lightboxImage,
        unreadCounts, appName, showAdminSettings, adminSettings, saveAdminSettings, isConnected, isAuthBusy,
        showScrollDown, scrollToBottom, scrollToMessage, openSavedView, unsave,
        showAccessModal, accessModalUser, accessChannels, accessMap, openAccessModal, toggleUserAccess,
        refreshAccessModal, accessDeniedBanner, safeLink,
        lpStartUser, lpStartMessage, lpMove, lpEnd, onComposerFocus, onComposerBlur,
      };
    },
  }).mount('#app');
})();
