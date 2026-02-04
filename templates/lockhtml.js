
/* lockhtml runtime v2 */
(function() {
  'use strict';

  const STORAGE_KEY = 'lockhtml_passwords';
  const CONFIG = {
    title: "Protected Content",
    buttonText: "Unlock",
    errorText: "Incorrect password",
    placeholder: "Enter password",
    usernamePlaceholder: "Enter username",
    defaultRemember: "ask",
    rememberDays: 0,
    autoPrompt: true
  };

  // Crypto utilities
  async function computeHash(content) {
    // Compute truncated SHA-256 hash for integrity verification
    // Must match Python's content_hash() implementation
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    // Truncate to first 16 bytes (128 bits) to match Python implementation
    const hashArray = new Uint8Array(hashBuffer).slice(0, 16);
    return Array.from(hashArray, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function deriveKey(secret, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 310000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptContent(encryptedBase64, password, username) {
    try {
      // Decode outer base64
      const jsonStr = atob(encryptedBase64);
      const data = JSON.parse(jsonStr);

      // Validate version
      if (data.v !== 2) throw new Error('Unsupported version: ' + data.v);

      // Decode components
      const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(data.ct), c => c.charCodeAt(0));

      // Build secret: "username:password" or just "password"
      const secret = username ? username + ':' + password : password;

      // ONE PBKDF2 derivation with shared salt
      const wrappingKey = await deriveKey(secret, salt);

      // Try each key blob to recover CEK
      let cek = null;
      for (const keyBlob of data.keys) {
        const blobIv = Uint8Array.from(atob(keyBlob.iv), c => c.charCodeAt(0));
        const blobCt = Uint8Array.from(atob(keyBlob.ct), c => c.charCodeAt(0));
        try {
          const rawCek = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: blobIv },
            wrappingKey,
            blobCt
          );
          cek = rawCek;
          break;
        } catch (e) {
          // Wrong key blob, try next
          continue;
        }
      }

      if (!cek) throw new Error('No matching key found');

      // Import recovered CEK
      const cekKey = await crypto.subtle.importKey(
        'raw',
        cek,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      // Decrypt content with CEK
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cekKey,
        ct
      );

      // Parse inner JSON wrapper
      const inner = JSON.parse(new TextDecoder().decode(decrypted));
      return { content: inner.c, meta: inner.m || null };
    } catch (e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }

  // Storage utilities
  function getStoredPasswords() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return {};
      const data = JSON.parse(stored);
      // Check expiration
      const now = Date.now();
      const filtered = {};
      for (const [key, value] of Object.entries(data)) {
        if (!value.expires || value.expires > now) {
          filtered[key] = value;
        }
      }
      return filtered;
    } catch {
      return {};
    }
  }

  function storeCredentials(password, username, remember) {
    if (remember === 'none') return;
    const cred = username ? { username, password } : { password };
    if (remember === 'session') {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(cred));
      return;
    }
    const data = getStoredPasswords();
    const expires = CONFIG.rememberDays > 0
      ? Date.now() + (CONFIG.rememberDays * 24 * 60 * 60 * 1000)
      : null;
    data[location.origin] = { ...cred, expires };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  function getStoredCredentials() {
    // Check session first
    const session = sessionStorage.getItem(STORAGE_KEY);
    if (session) {
      try {
        const cred = JSON.parse(session);
        return cred.password ? cred : { password: session };
      } catch {
        return { password: session };
      }
    }
    // Check localStorage
    const data = getStoredPasswords();
    const entry = data[location.origin];
    if (!entry) return null;
    return entry.password ? entry : null;
  }

  function clearStoredPasswords() {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
  }

  // URL fragment handling
  function checkFragment() {
    const hash = location.hash.slice(1);
    if (!hash) return null;

    if (hash === 'lockhtml_logout') {
      clearStoredPasswords();
      // Navigate without the hash — works on file:// unlike history.replaceState
      location.replace(location.pathname + location.search);
      return 'logout';
    }

    const match = hash.match(/^lockhtml_pwd=([^&]+)(&remember)?$/);
    if (match) {
      try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
      return {
        password: decodeURIComponent(match[1]),
        remember: match[2] ? 'local' : null
      };
    }

    return null;
  }

  // Web Component
  class LockhtmlEncrypt extends HTMLElement {
    constructor() {
      super();
      this._decrypted = false;
    }

    connectedCallback() {
      if (!this.hasAttribute('data-encrypted')) return;
      this._render();
      this._tryAutoDecrypt();
    }

    _render() {
      const hint = this.getAttribute('data-hint');
      const title = this.getAttribute('data-title') || CONFIG.title;
      const remember = this.getAttribute('data-remember') || CONFIG.defaultRemember;
      const isUserMode = this.getAttribute('data-mode') === 'user';

      this.innerHTML = `
        <div class="lockhtml-container">
          <div class="lockhtml-icon">🔒</div>
          <div class="lockhtml-title">${title}</div>
          ${hint ? `<div class="lockhtml-hint">${hint}</div>` : ''}
          <form class="lockhtml-form">
            ${isUserMode ? `<input type="text" class="lockhtml-input lockhtml-username" placeholder="${CONFIG.usernamePlaceholder}" autocomplete="username">` : ''}
            <input type="password" class="lockhtml-input" placeholder="${CONFIG.placeholder}" autocomplete="current-password">
            ${remember === 'ask' ? `
              <label class="lockhtml-remember">
                <input type="checkbox" name="remember">
                Remember on this device
              </label>
            ` : ''}
            <button type="submit" class="lockhtml-button">${CONFIG.buttonText}</button>
            <div class="lockhtml-error" style="display: none;"></div>
          </form>
        </div>
      `;

      const form = this.querySelector('form');
      const passwordInput = this.querySelector('input[type="password"]');
      const usernameInput = this.querySelector('.lockhtml-username');
      const error = this.querySelector('.lockhtml-error');

      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = passwordInput.value;
        if (!password) return;
        const username = usernameInput ? usernameInput.value : null;

        // Capture checkbox state BEFORE decryption replaces innerHTML
        const rememberCheckbox = this.querySelector('input[name="remember"]');
        const wantsRemember = remember === 'local' || (rememberCheckbox && rememberCheckbox.checked);

        const button = this.querySelector('button');
        button.disabled = true;
        button.textContent = 'Decrypting...';

        const success = await this._decrypt(password, username);

        if (!success) {
          error.textContent = CONFIG.errorText;
          error.style.display = 'block';
          button.disabled = false;
          button.textContent = CONFIG.buttonText;
          passwordInput.value = '';
          passwordInput.focus();
        } else {
          // Store credentials if requested
          if (wantsRemember) {
            storeCredentials(password, username, 'local');
          } else if (remember === 'session') {
            storeCredentials(password, username, 'session');
          }
        }
      });

      // Focus appropriate input if auto-prompt
      if (CONFIG.autoPrompt) {
        const focusTarget = usernameInput || passwordInput;
        setTimeout(() => focusTarget.focus(), 100);
      }
    }

    async _tryAutoDecrypt() {
      // Check URL fragment first
      const fragment = checkFragment();
      if (fragment === 'logout') return;

      let password = null;
      let username = null;
      let remember = null;

      if (fragment && fragment.password) {
        password = fragment.password;
        remember = fragment.remember;
      } else {
        const cred = getStoredCredentials();
        if (cred) {
          password = cred.password;
          username = cred.username || null;
        }
      }

      if (password) {
        const success = await this._decrypt(password, username);
        if (success && remember) {
          storeCredentials(password, username, remember);
        }
      }
    }

    async _decrypt(password, username) {
      const encrypted = this.getAttribute('data-encrypted');
      if (!encrypted) return false;

      const expectedHash = this.getAttribute('data-content-hash');

      const result = await decryptContent(encrypted, password, username);
      if (result === null) return false;

      const content = result.content;
      const meta = result.meta;

      // Verify content hash if present
      if (expectedHash) {
        const actualHash = await computeHash(content);
        if (actualHash !== expectedHash) {
          console.error('Content hash mismatch - decryption may be corrupted');
          return false;
        }
      }

      // Remove encrypted attributes and reveal content
      this.removeAttribute('data-encrypted');
      this.removeAttribute('data-content-hash');
      this.removeAttribute('data-mode');
      this.innerHTML = content;
      this._decrypted = true;

      // Dispatch event for scripts that need to know
      this.dispatchEvent(new CustomEvent('lockhtml:decrypted', {
        bubbles: true,
        detail: { element: this, meta: meta }
      }));

      return true;
    }
  }

  // Register component
  if (!customElements.get('lockhtml-encrypt')) {
    customElements.define('lockhtml-encrypt', LockhtmlEncrypt);
  }
})();
