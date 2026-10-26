/*! yd-captcha browser SDK v0.1.0 | 浏览器验证码 SDK */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(root);
  } else {
    root.YdCaptcha = factory(root);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
  'use strict';

  var VERSION = '0.1.0';
  var MAX_TRACK = 512;

  var LABELS_ZH = {
    submit: '验证',
    refresh: '换一张',
    send: '发送验证码',
    resend: '重新发送',
    targetPhone: '手机号',
    targetEmail: '邮箱',
    code: '请输入验证码',
    loading: '加载中…',
    verifying: '验证中…',
    success: '验证通过',
    failed: '验证失败，请重试',
    scratch: '刮开涂层后输入字符',
    reset: '重置',
    clickHint: '请按提示点击图片',
    rotateHint: '拖动滑块校正方向',
    network: '网络异常，请重试',
    captureBlocked: '检测到截屏或录屏操作，请停止后重新验证',
    fallbackSMS: '检测到截屏或录屏，已切换为短信验证',
    fallbackEmail: '检测到截屏或录屏，已切换为邮箱验证',
    backToImage: '返回图形验证',
    smsVerify: '短信验证',
    emailVerify: '邮箱验证',
    unsupported: '不支持的验证类型'
  };

  var LABELS_EN = {
    submit: 'Verify',
    refresh: 'Refresh',
    send: 'Send code',
    resend: 'Resend',
    targetPhone: 'Phone number',
    targetEmail: 'Email address',
    code: 'Enter the code',
    loading: 'Loading…',
    verifying: 'Verifying…',
    success: 'Verified',
    failed: 'Verification failed, please retry',
    scratch: 'Scratch the coating and type the characters',
    reset: 'Reset',
    clickHint: 'Click the image as instructed',
    rotateHint: 'Drag the slider to correct the angle',
    network: 'Network error, please retry',
    captureBlocked: 'Screen capture detected; stop recording and retry',
    fallbackSMS: 'Capture detected; switched to SMS verification',
    fallbackEmail: 'Capture detected; switched to email verification',
    backToImage: 'Back to image challenge',
    smsVerify: 'SMS verification',
    emailVerify: 'Email verification',
    unsupported: 'Unsupported challenge type'
  };

  // Build-time injection point; scripts/build.mjs replaces this with every
  // locale catalog from captcha/langs. | 构建时注入点；scripts/build.mjs 会用
  // captcha/langs 中的全部语言目录替换它。
  var LABELS_CATALOG = {"de":{"submit":"Bestätigen","refresh":"Aktualisieren","send":"Code senden","resend":"Erneut senden","targetPhone":"Telefonnummer","targetEmail":"E-Mail-Adresse","code":"Code eingeben","loading":"Wird geladen…","verifying":"Wird geprüft…","success":"Verifiziert","failed":"Verifizierung fehlgeschlagen, bitte erneut versuchen","scratch":"Beschichtung freirubbeln und Zeichen eingeben","reset":"Zurücksetzen","clickHint":"Klicken Sie wie angegeben auf das Bild","rotateHint":"Ziehen Sie den Regler, um den Winkel zu korrigieren","network":"Netzwerkfehler, bitte erneut versuchen","captureBlocked":"Bildschirmaufnahme erkannt; beenden und erneut versuchen","fallbackSMS":"Aufnahme erkannt; auf SMS-Verifizierung umgestellt","fallbackEmail":"Aufnahme erkannt; auf E-Mail-Verifizierung umgestellt","backToImage":"Zurück zur Bildprüfung","smsVerify":"SMS-Verifizierung","emailVerify":"E-Mail-Verifizierung","unsupported":"Nicht unterstützter Prüfungstyp"},"en":{"submit":"Verify","refresh":"Refresh","send":"Send code","resend":"Resend","targetPhone":"Phone number","targetEmail":"Email address","code":"Enter the code","loading":"Loading…","verifying":"Verifying…","success":"Verified","failed":"Verification failed, please retry","scratch":"Scratch the coating and type the characters","reset":"Reset","clickHint":"Click the image as instructed","rotateHint":"Drag the slider to correct the angle","network":"Network error, please retry","captureBlocked":"Screen capture detected; stop recording and retry","fallbackSMS":"Capture detected; switched to SMS verification","fallbackEmail":"Capture detected; switched to email verification","backToImage":"Back to image challenge","smsVerify":"SMS verification","emailVerify":"Email verification","unsupported":"Unsupported challenge type"},"es":{"submit":"Verificar","refresh":"Actualizar","send":"Enviar código","resend":"Reenviar","targetPhone":"Número de teléfono","targetEmail":"Correo electrónico","code":"Introduce el código","loading":"Cargando…","verifying":"Verificando…","success":"Verificado","failed":"La verificación falló, inténtalo de nuevo","scratch":"Raspa la capa e introduce los caracteres","reset":"Restablecer","clickHint":"Haz clic en la imagen según las instrucciones","rotateHint":"Arrastra el control para corregir el ángulo","network":"Error de red, inténtalo de nuevo","captureBlocked":"Captura de pantalla detectada; detente e inténtalo de nuevo","fallbackSMS":"Captura detectada; se cambió a verificación por SMS","fallbackEmail":"Captura detectada; se cambió a verificación por correo","backToImage":"Volver al desafío de imagen","smsVerify":"Verificación por SMS","emailVerify":"Verificación por correo","unsupported":"Tipo de desafío no compatible"},"fr":{"submit":"Vérifier","refresh":"Actualiser","send":"Envoyer le code","resend":"Renvoyer","targetPhone":"Numéro de téléphone","targetEmail":"Adresse e-mail","code":"Saisissez le code","loading":"Chargement…","verifying":"Vérification…","success":"Vérifié","failed":"Échec de la vérification, réessayez","scratch":"Grattez le revêtement et saisissez les caractères","reset":"Réinitialiser","clickHint":"Cliquez sur l’image comme indiqué","rotateHint":"Faites glisser le curseur pour corriger l’angle","network":"Erreur réseau, réessayez","captureBlocked":"Capture d’écran détectée ; arrêtez et réessayez","fallbackSMS":"Capture détectée ; passage à la vérification par SMS","fallbackEmail":"Capture détectée ; passage à la vérification par e-mail","backToImage":"Revenir au défi visuel","smsVerify":"Vérification par SMS","emailVerify":"Vérification par e-mail","unsupported":"Type de défi non pris en charge"},"ja":{"submit":"認証","refresh":"更新","send":"コードを送信","resend":"再送信","targetPhone":"電話番号","targetEmail":"メールアドレス","code":"コードを入力してください","loading":"読み込み中…","verifying":"確認中…","success":"認証に成功しました","failed":"認証に失敗しました。再試行してください","scratch":"コーティングを削って文字を入力してください","reset":"リセット","clickHint":"指示に従って画像をクリックしてください","rotateHint":"スライダーで角度を修正してください","network":"ネットワークエラーです。再試行してください","captureBlocked":"画面キャプチャを検出しました。停止して再試行してください","fallbackSMS":"画面キャプチャを検出したため、SMS認証に切り替えました","fallbackEmail":"画面キャプチャを検出したため、メール認証に切り替えました","backToImage":"画像認証に戻る","smsVerify":"SMS認証","emailVerify":"メール認証","unsupported":"サポートされていない認証タイプ"},"ko":{"submit":"인증","refresh":"새로고침","send":"인증번호 보내기","resend":"다시 보내기","targetPhone":"휴대폰 번호","targetEmail":"이메일 주소","code":"인증번호를 입력하세요","loading":"불러오는 중…","verifying":"확인 중…","success":"인증되었습니다","failed":"인증에 실패했습니다. 다시 시도하세요","scratch":"코팅을 긁고 문자를 입력하세요","reset":"초기화","clickHint":"안내에 따라 이미지를 클릭하세요","rotateHint":"슬라이더로 각도를 조정하세요","network":"네트워크 오류입니다. 다시 시도하세요","captureBlocked":"화면 캡처가 감지되었습니다. 중지 후 다시 시도하세요","fallbackSMS":"화면 캡처가 감지되어 SMS 인증으로 전환했습니다","fallbackEmail":"화면 캡처가 감지되어 이메일 인증으로 전환했습니다","backToImage":"이미지 인증으로 돌아가기","smsVerify":"SMS 인증","emailVerify":"이메일 인증","unsupported":"지원되지 않는 인증 유형"},"zh-CN":{"submit":"验证","refresh":"换一张","send":"发送验证码","resend":"重新发送","targetPhone":"手机号","targetEmail":"邮箱","code":"请输入验证码","loading":"加载中…","verifying":"验证中…","success":"验证通过","failed":"验证失败，请重试","scratch":"刮开涂层后输入字符","reset":"重置","clickHint":"请按提示点击图片","rotateHint":"拖动滑块校正方向","network":"网络异常，请重试","captureBlocked":"检测到截屏或录屏操作，请停止后重新验证","fallbackSMS":"检测到截屏或录屏，已切换为短信验证","fallbackEmail":"检测到截屏或录屏，已切换为邮箱验证","backToImage":"返回图形验证","smsVerify":"短信验证","emailVerify":"邮箱验证","unsupported":"不支持的验证类型"},"zh-TW":{"submit":"驗證","refresh":"換一張","send":"傳送驗證碼","resend":"重新傳送","targetPhone":"手機號碼","targetEmail":"電子郵件","code":"請輸入驗證碼","loading":"載入中…","verifying":"驗證中…","success":"驗證通過","failed":"驗證失敗，請重試","scratch":"刮開塗層後輸入字元","reset":"重設","clickHint":"請依提示點擊圖片","rotateHint":"拖曳滑桿校正方向","network":"網路異常，請重試","captureBlocked":"偵測到截圖或錄影操作，請停止後重新驗證","fallbackSMS":"偵測到截圖或錄影，已切換為簡訊驗證","fallbackEmail":"偵測到截圖或錄影，已切換為電子郵件驗證","backToImage":"返回圖形驗證","smsVerify":"簡訊驗證","emailVerify":"電子郵件驗證","unsupported":"不支援的驗證類型"}};

  function isHanLocale(locale) {
    return String(locale || '').toLowerCase().indexOf('zh') === 0;
  }

  function matchLocale(input) {
    var tag = String(input || '').replace(/_/g, '-').trim();
    var lower = tag.toLowerCase();
    if (!lower) return '';
    if (lower === 'zh' || lower === 'zh-cn' || lower === 'zh-sg' || lower.indexOf('zh-hans') === 0) return 'zh-CN';
    if (lower === 'zh-tw' || lower === 'zh-hk' || lower === 'zh-mo' || lower.indexOf('zh-hant') === 0) return 'zh-TW';
    var locales = Object.keys(LABELS_CATALOG);
    for (var i = 0; i < locales.length; i++) {
      if (locales[i].toLowerCase() === lower) return locales[i];
    }
    var primary = lower.split('-')[0];
    for (var j = 0; j < locales.length; j++) {
      if (locales[j].toLowerCase().split('-')[0] === primary) return locales[j];
    }
    return '';
  }

  function normalizeLocale(input) {
    var tag = String(input || '').replace(/_/g, '-').trim();
    if (!tag) return 'en';
    // Preserve unknown tags so a host-backed catalog can handle them; UI labels
    // fall back to English until a bundled catalog exists. | 保留未知标签，供宿主
    // 目录处理；在打包目录存在前，界面文案回退英文。
    return matchLocale(tag) || tag;
  }

  function preferredLocale(options) {
    if (options && options.locale) return normalizeLocale(options.locale);
    var nav = root.navigator || {};
    var languages = Array.isArray(nav.languages) && nav.languages.length ? nav.languages : [nav.language];
    for (var i = 0; i < languages.length; i++) {
      var matched = matchLocale(languages[i]);
      if (matched) return matched;
    }
    return normalizeLocale(languages[0] || 'en');
  }

  function labelsFor(options) {
    var locale = preferredLocale(options);
    var base = LABELS_CATALOG[locale] || (isHanLocale(locale) ? LABELS_ZH : LABELS_EN);
    var custom = options && options.labels ? options.labels : {};
    var out = {};
    function merge(source) {
      for (var key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
      }
    }
    merge(LABELS_EN);
    merge(base);
    merge(custom);
    return out;
  }

  function hasDOM() {
    return typeof root.document !== 'undefined' && !!root.document.createElement;
  }

  function make(tag, className, text) {
    var node = root.document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function joinURL(endpoint, path) {
    if (/^https?:\/\//i.test(path)) return path;
    var base = String(endpoint || '/captcha').replace(/\/+$/, '');
    var suffix = String(path || '').replace(/^\/+/, '');
    return base + '/' + suffix;
  }

  function errorFrom(data, status) {
    var err = new Error((data && data.error && data.error.message) || 'captcha request failed');
    err.code = data && data.error ? data.error.code : 'request_failed';
    err.status = status;
    err.retryAfter = data && data.error ? data.error.retry_after : 0;
    return err;
  }

  function requestJSON(fetchImpl, url, body, headers, signal) {
    var merged = { 'Content-Type': 'application/json' };
    if (headers) {
      for (var key in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, key)) merged[key] = headers[key];
      }
    }
    return fetchImpl(url, {
      method: 'POST',
      headers: merged,
      body: JSON.stringify(body || {}),
      signal: signal,
      credentials: 'same-origin'
    }).then(function (response) {
      return response.json().catch(function () {
        throw errorFrom(null, response.status);
      }).then(function (data) {
        if (!response.ok || !data || !data.ok) {
          throw errorFrom(data, response.status);
        }
        return data;
      });
    });
  }

  function hashString(input) {
    var hash = 2166136261;
    for (var i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function canvasFingerprint() {
    if (!hasDOM()) return '';
    var canvas = root.document.createElement('canvas');
    canvas.width = 96;
    canvas.height = 32;
    var ctx = canvas.getContext('2d');
    if (!ctx) return '';
    ctx.textBaseline = 'top';
    ctx.font = '16px sans-serif';
    ctx.fillStyle = '#f60';
    ctx.fillRect(0, 0, 96, 32);
    ctx.fillStyle = '#069';
    ctx.fillText('yd-captcha 验证码', 2, 2);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('yd-captcha 验证码', 4, 15);
    try {
      return canvas.toDataURL();
    } catch (_) {
      return '';
    }
  }

  function webglFingerprint() {
    if (!hasDOM()) return '';
    try {
      var canvas = root.document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return '';
      var info = gl.getExtension('WEBGL_debug_renderer_info');
      if (!info) return '';
      return String(gl.getParameter(info.UNMASKED_VENDOR_WEBGL)) + '|' + String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL));
    } catch (_) {
      return '';
    }
  }

  var cachedTimezone = null;
  var cachedCanvasHash = null;
  var cachedWebglHash = null;

  function collectSignals(tracker, capture) {
    var nav = root.navigator || {};
    var screenObj = root.screen || {};
    var guard = capture || {};
    var signals = {
      user_agent: String(nav.userAgent || ''),
      platform: String(nav.platform || ''),
      language: String(nav.language || ''),
      languages: Array.isArray(nav.languages) ? nav.languages.slice(0, 8) : [],
      timezone: '',
      screen_width: Number(screenObj.width || 0),
      screen_height: Number(screenObj.height || 0),
      color_depth: Number(screenObj.colorDepth || 0),
      device_memory: Number(nav.deviceMemory || 0),
      hardware_concurrency: Number(nav.hardwareConcurrency || 0),
      touch: !!(('ontouchstart' in root) || (nav.maxTouchPoints && nav.maxTouchPoints > 0)),
      webdriver: !!nav.webdriver,
      headless: /HeadlessChrome/i.test(String(nav.userAgent || '')),
      plugins: nav.plugins ? Number(nav.plugins.length || 0) : 0,
      cookie_enabled: !!nav.cookieEnabled,
      do_not_track: nav.doNotTrack || root.doNotTrack || '',
      visibility: root.document ? String(root.document.visibilityState || '') : '',
      screen_capture: !!guard.screen_capture,
      screenshot_key: !!guard.screenshot_key,
      print_attempt: !!guard.print_attempt,
      page_hidden: !!guard.page_hidden,
      focus_loss: Number(guard.focus_loss || 0) + (root.document && root.document.hasFocus && !root.document.hasFocus() ? 1 : 0)
    };
    if (cachedTimezone === null) {
      try {
        cachedTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      } catch (_) {
        cachedTimezone = '';
      }
    }
    signals.timezone = cachedTimezone;
    if (cachedCanvasHash === null) {
      try {
        var canvasHash = canvasFingerprint();
        cachedCanvasHash = canvasHash ? hashString(canvasHash) : '';
      } catch (_) {
        cachedCanvasHash = '';
      }
    }
    signals.canvas_hash = cachedCanvasHash;
    if (cachedWebglHash === null) {
      try {
        cachedWebglHash = hashString(webglFingerprint());
      } catch (_) {
        cachedWebglHash = '';
      }
    }
    signals.webgl_hash = cachedWebglHash;
    if (tracker) {
      signals.mouse_entropy = tracker.entropy();
    }
    return signals;
  }

  function screenshotShortcut(event) {
    if (!event) return '';
    var key = String(event.key || '');
    if (key === 'PrintScreen' || key === 'Print' || event.code === 'PrintScreen') {
      return 'screenshot_key';
    }
    if ((event.metaKey || event.ctrlKey) && event.shiftKey && (key === '3' || key === '4' || key === '5')) {
      return 'screenshot_key';
    }
    if (event.ctrlKey && event.shiftKey && (key === 's' || key === 'S')) {
      return 'screenshot_key';
    }
    return '';
  }

  function toBytes(text) {
    var bytes = new Array(text.length);
    for (var i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 255;
    return bytes;
  }

  var SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(value, shift) {
    return (value >>> shift) | (value << (32 - shift));
  }

  function sha256Bytes(bytes) {
    var length = bytes.length;
    var bitLength = length * 8;
    var paddedLength = (((length + 8) >> 6) + 1) << 6;
    var data = new Uint8Array(paddedLength);
    for (var i = 0; i < length; i++) data[i] = bytes[i];
    data[length] = 0x80;
    data[paddedLength - 4] = (bitLength >>> 24) & 255;
    data[paddedLength - 3] = (bitLength >>> 16) & 255;
    data[paddedLength - 2] = (bitLength >>> 8) & 255;
    data[paddedLength - 1] = bitLength & 255;

    var h0 = 0x6a09e667;
    var h1 = 0xbb67ae85;
    var h2 = 0x3c6ef372;
    var h3 = 0xa54ff53a;
    var h4 = 0x510e527f;
    var h5 = 0x9b05688c;
    var h6 = 0x1f83d9ab;
    var h7 = 0x5be0cd19;
    var w = new Array(64);

    for (var offset = 0; offset < paddedLength; offset += 64) {
      for (var t = 0; t < 16; t++) {
        var pos = offset + t * 4;
        w[t] = ((data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]) >>> 0;
      }
      for (var u = 16; u < 64; u++) {
        var s0 = (rotr(w[u - 15], 7) ^ rotr(w[u - 15], 18) ^ (w[u - 15] >>> 3)) >>> 0;
        var s1 = (rotr(w[u - 2], 17) ^ rotr(w[u - 2], 19) ^ (w[u - 2] >>> 10)) >>> 0;
        w[u] = (w[u - 16] + s0 + w[u - 7] + s1) >>> 0;
      }
      var a = h0;
      var b = h1;
      var c = h2;
      var d = h3;
      var e = h4;
      var f = h5;
      var g = h6;
      var h = h7;
      for (var v = 0; v < 64; v++) {
        var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
        var ch = ((e & f) ^ ((~e) & g)) >>> 0;
        var temp1 = (h + S1 + ch + SHA256_K[v] + w[v]) >>> 0;
        var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
        var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        var temp2 = (S0 + maj) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    var out = new Uint8Array(32);
    var words = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (var n = 0; n < 8; n++) {
      out[n * 4] = (words[n] >>> 24) & 255;
      out[n * 4 + 1] = (words[n] >>> 16) & 255;
      out[n * 4 + 2] = (words[n] >>> 8) & 255;
      out[n * 4 + 3] = words[n] & 255;
    }
    return out;
  }

  function leadingZeroBits(bytes) {
    var count = 0;
    for (var i = 0; i < bytes.length; i++) {
      var value = bytes[i];
      if (value === 0) {
        count += 8;
        continue;
      }
      var mask = 128;
      while ((value & mask) === 0) {
        count++;
        mask >>= 1;
      }
      return count;
    }
    return count;
  }

  function solvePoW(pow) {
    if (!pow || pow.algorithm !== 'sha256' || !pow.seed) {
      return Promise.reject(new Error('unsupported proof of work'));
    }
    var difficulty = Number(pow.difficulty || 0);
    var nonce = 0;
    return new Promise(function (resolve, reject) {
      function step() {
        var deadline = Date.now() + 25;
        while (nonce < 0xffffffff) {
          var digest = sha256Bytes(toBytes(pow.seed + ':' + nonce));
          if (leadingZeroBits(digest) >= difficulty) {
            resolve({ nonce: nonce });
            return;
          }
          nonce++;
          if (Date.now() > deadline) {
            setTimeout(step, 0);
            return;
          }
        }
        reject(new Error('proof of work exhausted'));
      }
      step();
    });
  }

  function Tracker() {
    this.points = [];
    this.started = null;
    this.ended = null;
  }

  Tracker.prototype.add = function (kind, x, y) {
    if (this.points.length >= MAX_TRACK) return;
    var now = Math.round((root.performance && root.performance.now) ? root.performance.now() : Date.now());
    if (this.started === null) this.started = now;
    this.ended = now;
    this.points.push({ t: now - this.started, x: Math.round(x), y: Math.round(y), kind: kind });
  };

  Tracker.prototype.track = function () {
    var duration = this.ended === null || this.started === null ? 0 : this.ended - this.started;
    return { started_at: 0, ended_at: duration, points: this.points.slice(0) };
  };

  Tracker.prototype.entropy = function () {
    if (this.points.length < 4) return 0;
    var sum = 0;
    var count = 0;
    var prev = null;
    for (var i = 0; i < this.points.length; i++) {
      var point = this.points[i];
      if (prev) {
        var dx = point.x - prev.x;
        var dy = point.y - prev.y;
        if (dx !== 0 || dy !== 0) {
          sum += Math.atan2(dy, dx);
          count++;
        }
      }
      prev = point;
    }
    if (count < 2) return 0;
    var mean = sum / count;
    var variance = 0;
    prev = null;
    for (var j = 0; j < this.points.length; j++) {
      var current = this.points[j];
      if (prev) {
        var ddx = current.x - prev.x;
        var ddy = current.y - prev.y;
        if (ddx !== 0 || ddy !== 0) {
          var diff = Math.atan2(ddy, ddx) - mean;
          variance += diff * diff;
        }
      }
      prev = current;
    }
    return Math.sqrt(variance / count);
  };

  function freshCaptureState() {
    return {
      screen_capture: false,
      screenshot_key: false,
      print_attempt: false,
      page_hidden: false,
      focus_loss: 0
    };
  }

  function Widget(container, options) {
    if (!hasDOM()) throw new Error('YdCaptcha requires a browser DOM');
    this.container = typeof container === 'string' ? root.document.querySelector(container) : container;
    if (!this.container) throw new Error('YdCaptcha mount target not found');
    this.options = options || {};
    this.options.endpoint = this.options.endpoint || '/captcha';
    this.options.action = this.options.action || 'default';
    this.options.locale = normalizeLocale(this.options.locale || (root.navigator && root.navigator.language) || 'en');
    this.options.headers = this.options.headers || {};
    this.labels = labelsFor(this.options);
    this.fetchImpl = this.options.fetch || (typeof root.fetch === 'function' ? root.fetch.bind(root) : null);
    if (!this.fetchImpl) throw new Error('YdCaptcha requires fetch');
    this.cleanup = [];
    this.guardCleanup = [];
    this.displayCaptureRestore = null;
    this.tracker = new Tracker();
    this.captureState = freshCaptureState();
    this.blockedByCapture = false;
    this.fallbackActive = false;
    this.fallbackChannel = '';
    this.fallbackKind = '';
    this.fallbackNotice = '';
    this.challenge = null;
    this.busy = false;
    this.destroyed = false;
    this.answerReset = null;
    this.themeHandler = null;
    this.build();
    this.setTheme(this.options.theme || 'auto');
    if (this.options.captureGuard !== false) this.installCaptureGuard();
    if (this.options.autoStart !== false) this.start();
  }

  Widget.prototype.build = function () {
    this.root = make('div', 'yd-captcha');
    this.root.setAttribute('data-theme', 'auto');
    this.root.setAttribute('role', 'group');
    this.root.setAttribute('aria-label', 'captcha verification');
    this.promptEl = make('div', 'yd-captcha__prompt');
    this.promptEl.setAttribute('aria-live', 'polite');
    this.hintEl = make('div', 'yd-captcha__hint');
    this.noticeEl = make('div', 'yd-captcha__notice');
    this.noticeEl.setAttribute('role', 'status');
    this.noticeEl.setAttribute('aria-live', 'polite');
    this.noticeEl.hidden = true;
    this.stageEl = make('div', 'yd-captcha__stage');
    this.statusEl = make('div', 'yd-captcha__status');
    this.statusEl.setAttribute('aria-live', 'polite');
    this.actionsEl = make('div', 'yd-captcha__actions');
    this.root.appendChild(this.promptEl);
    this.root.appendChild(this.hintEl);
    this.root.appendChild(this.noticeEl);
    this.root.appendChild(this.stageEl);
    this.root.appendChild(this.actionsEl);
    this.root.appendChild(this.statusEl);
    this.container.appendChild(this.root);
    this.signal = null;
  };

  Widget.prototype.bind = function (target, event, handler, options) {
    target.addEventListener(event, handler, options);
    this.cleanup.push(function () { target.removeEventListener(event, handler, options); });
  };

  Widget.prototype.bindGuard = function (target, event, handler, options) {
    target.addEventListener(event, handler, options);
    this.guardCleanup.push(function () { target.removeEventListener(event, handler, options); });
  };

  Widget.prototype.installCaptureGuard = function () {
    var self = this;
    var doc = root.document;
    function stop(event) {
      if (event && event.preventDefault) event.preventDefault();
    }
    this.bindGuard(this.root, 'contextmenu', stop);
    this.bindGuard(this.root, 'copy', stop);
    this.bindGuard(this.root, 'cut', stop);
    this.bindGuard(this.root, 'dragstart', stop);
    this.bindGuard(this.root, 'selectstart', stop);
    this.bindGuard(root, 'beforeprint', function () { self.markCapture('print_attempt'); });
    this.bindGuard(root, 'keydown', function (event) {
      var kind = screenshotShortcut(event);
      if (!kind) return;
      stop(event);
      self.markCapture(kind);
    });
    this.bindGuard(root, 'blur', function () { self.markCapture('focus_loss'); });
    this.bindGuard(doc, 'visibilitychange', function () {
      if (doc.visibilityState === 'hidden') self.markCapture('page_hidden');
    });
    try {
      var nav = root.navigator || {};
      var media = nav.mediaDevices;
      if (media && typeof media.getDisplayMedia === 'function') {
        var original = media.getDisplayMedia;
        var wrapped = function () {
          if (self.destroyed) return original.apply(media, arguments);
          self.markCapture('screen_capture');
          if (self.options.blockDisplayCapture !== false) {
            return Promise.reject(new Error('screen capture blocked | 录屏已被阻止'));
          }
          return original.apply(media, arguments);
        };
        media.getDisplayMedia = wrapped;
        self.displayCaptureRestore = function () {
          if (media.getDisplayMedia === wrapped) media.getDisplayMedia = original;
        };
      }
    } catch (_) {}
  };

  Widget.prototype.clearCaptureState = function () {
    this.captureState = freshCaptureState();
    this.blockedByCapture = false;
  };

  Widget.prototype.resetCapture = function () {
    this.clearCaptureState();
    this.setStatus('');
  };

  Widget.prototype.markCapture = function (kind) {
    if (this.destroyed || !this.captureState) return;
    if (kind === 'focus_loss') {
      this.captureState.focus_loss++;
    } else if (kind === 'page_hidden') {
      this.captureState.page_hidden = true;
    } else if (kind === 'screen_capture') {
      this.captureState.screen_capture = true;
    } else if (kind === 'screenshot_key') {
      this.captureState.screenshot_key = true;
    } else if (kind === 'print_attempt') {
      this.captureState.print_attempt = true;
    }
    if (typeof this.options.onCapture === 'function') {
      try {
        this.options.onCapture({ kind: kind, challengeId: this.challenge ? this.challenge.id : '' });
      } catch (_) {}
    }
    if (kind === 'focus_loss' || kind === 'page_hidden') return;
    if (this.signal) this.signal.abort();
    if (this.options.fallback === 'sms' || this.options.fallback === 'email') {
      this.fallbackTo(this.options.fallback, kind);
      return;
    }
    var action = this.options.captureAction || 'block';
    if (action === 'ignore') return;
    if (action === 'refresh') {
      this.start();
      return;
    }
    this.blockedByCapture = true;
    this.setStatus(this.labels.captureBlocked, 'error');
    if (this.actionsEl && !this.actionsEl.querySelector('button')) this.addRefresh();
  };

  Widget.prototype.fallbackNoticeText = function (channel, kind) {
    var custom = this.options.fallbackNotice;
    if (typeof custom === 'function') {
      try {
        var value = custom({ channel: channel, kind: kind, locale: this.options.locale });
        if (typeof value === 'string' && value) return value;
      } catch (_) {}
    }
    if (typeof custom === 'string' && custom) return custom;
    return channel === 'email' ? this.labels.fallbackEmail : this.labels.fallbackSMS;
  };

  Widget.prototype.setNotice = function (text, kind) {
    this.noticeEl.textContent = text || '';
    this.noticeEl.hidden = !text;
    this.noticeEl.className = 'yd-captcha__notice' + (kind ? ' yd-captcha__notice--' + kind : '');
  };

  Widget.prototype.fallbackTo = function (channel, kind) {
    if (this.destroyed) return;
    if (channel !== 'sms' && channel !== 'email') return;
    this.fallbackActive = true;
    this.fallbackChannel = channel;
    this.fallbackKind = kind || 'screen_capture';
    this.fallbackNotice = this.fallbackNoticeText(channel, this.fallbackKind);
    if (this.signal) this.signal.abort();
    // The downgraded code flow is now the mitigation; do not make the code
    // verification itself inherit the capture rejection. | 降级后的验证码流程就是缓解措施，
    // 不应让验证码校验继续继承录屏拒绝。
    this.captureState = freshCaptureState();
    this.busy = false;
    this.blockedByCapture = false;
    this.challenge = null;
    this.tracker = new Tracker();
    this.renderCodeForm();
    this.setNotice(this.fallbackNotice, 'warning');
    this.setStatus('');
    if (typeof this.options.onFallback === 'function') {
      try {
        this.options.onFallback({ kind: this.fallbackKind, channel: channel, notice: this.fallbackNotice });
      } catch (_) {}
    }
  };

  Widget.prototype.bindPointer = function (target, handlers) {
    if (typeof root.PointerEvent === 'function') {
      if (handlers.down) this.bind(target, 'pointerdown', handlers.down);
      if (handlers.move) this.bind(target, 'pointermove', handlers.move);
      if (handlers.up) this.bind(target, 'pointerup', handlers.up);
      if (handlers.cancel || handlers.up) {
        this.bind(target, 'pointercancel', handlers.cancel || handlers.up);
      }
      return;
    }
    var active = false;
    function point(event) {
      var touch = (event.touches && event.touches[0]) || (event.changedTouches && event.changedTouches[0]);
      return {
        clientX: touch ? touch.clientX : event.clientX,
        clientY: touch ? touch.clientY : event.clientY,
        pointerId: 1,
        preventDefault: function () { event.preventDefault(); },
        currentTarget: target
      };
    }
    if (handlers.down) {
      this.bind(target, 'mousedown', function (event) { active = true; handlers.down(event); });
      this.bind(target, 'touchstart', function (event) { active = true; handlers.down(point(event)); }, { passive: false });
    }
    var follow = root.document || target;
    if (handlers.move) {
      this.bind(follow, 'mousemove', function (event) { if (active) handlers.move(point(event)); });
      this.bind(follow, 'touchmove', function (event) {
        if (active) {
          handlers.move(point(event));
          event.preventDefault();
        }
      }, { passive: false });
    }
    if (handlers.up) {
      this.bind(follow, 'mouseup', function (event) { if (active) { active = false; handlers.up(point(event)); } });
      this.bind(follow, 'touchend', function (event) { if (active) { active = false; handlers.up(point(event)); } });
    }
    if (handlers.cancel || handlers.up) {
      this.bind(follow, 'touchcancel', function (event) {
        if (!active) return;
        active = false;
        if (handlers.cancel) handlers.cancel(point(event));
        else handlers.up(point(event));
      });
    }
  };

  Widget.prototype.clearStage = function () {
    for (var i = 0; i < this.cleanup.length; i++) {
      try { this.cleanup[i](); } catch (_) {}
    }
    this.cleanup = [];
    this.answerReset = null;
    this.noticeEl.textContent = '';
    this.noticeEl.hidden = true;
    this.stageEl.innerHTML = '';
    this.actionsEl.innerHTML = '';
    this.statusEl.textContent = '';
    this.statusEl.className = 'yd-captcha__status';
  };

  Widget.prototype.destroy = function () {
    this.destroyed = true;
    if (this.signal) this.signal.abort();
    if (this.themeHandler && this.themeListener) {
      try { this.themeHandler.removeEventListener('change', this.themeListener); } catch (_) {}
      this.themeHandler = null;
      this.themeListener = null;
    }
    for (var i = 0; i < this.guardCleanup.length; i++) {
      try { this.guardCleanup[i](); } catch (_) {}
    }
    this.guardCleanup = [];
    if (this.displayCaptureRestore) {
      try { this.displayCaptureRestore(); } catch (_) {}
      this.displayCaptureRestore = null;
    }
    this.clearStage();
    if (this.root && this.root.parentNode) this.root.parentNode.removeChild(this.root);
  };

  Widget.prototype.setStatus = function (text, kind) {
    this.statusEl.textContent = text || '';
    this.statusEl.className = 'yd-captcha__status' + (kind ? ' yd-captcha__status--' + kind : '');
  };

  Widget.prototype.request = function (path, body) {
    if (this.signal) this.signal.abort();
    this.signal = typeof root.AbortController === 'function' ? new root.AbortController() : null;
    var signal = this.signal ? this.signal.signal : undefined;
    return requestJSON(this.fetchImpl, joinURL(this.options.endpoint, path), body, this.options.headers, signal);
  };

  Widget.prototype.start = function () {
    if (this.destroyed) return Promise.resolve();
    if (this.signal) this.signal.abort();
    this.busy = false;
    this.fallbackActive = false;
    this.fallbackChannel = '';
    this.fallbackKind = '';
    this.fallbackNotice = '';
    // A new challenge must not inherit pointer samples from the previous one. | 新挑战不能继承上一次的指针轨迹。
    this.tracker = new Tracker();
    this.clearCaptureState();
    this.clearStage();
    if (this.isCodeType()) {
      this.renderCodeForm();
      return Promise.resolve();
    }
    var self = this;
    this.setStatus(this.labels.loading);
    return this.request('challenge', {
      type: this.options.type || undefined,
      action: this.options.action,
      locale: this.options.locale,
      signals: collectSignals(this.tracker, this.captureState)
    }).then(function (data) {
      self.challenge = data.challenge;
      self.renderChallenge();
      self.setStatus('');
      if (typeof self.options.onReady === 'function') self.options.onReady(self.challenge);
    }).catch(function (err) {
      self.handleError(err);
    });
  };

  Widget.prototype.refresh = function () { return this.start(); };

  Widget.prototype.setLocale = function (locale) {
    this.options.locale = normalizeLocale(locale);
    this.labels = labelsFor(this.options);
    return this.start();
  };

  function normalizeTheme(theme) {
    var value = String(theme || 'auto').toLowerCase();
    if (value === 'system') return 'auto';
    if (value === 'light' || value === 'dark' || value === 'auto') return value;
    return 'auto';
  }

  Widget.prototype.resolvedTheme = function () {
    var theme = normalizeTheme(this.options.theme);
    if (theme !== 'auto') return theme;
    try {
      return root.matchMedia && root.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    } catch (_) {
      return 'light';
    }
  };

  Widget.prototype.setTheme = function (theme) {
    var normalized = normalizeTheme(theme);
    var previous = this.resolvedTheme();
    this.options.theme = normalized;
    this.root.setAttribute('data-theme', normalized);
    this.root.setAttribute('data-resolved-theme', this.resolvedTheme());
    if (this.themeHandler) {
      try { this.themeHandler.removeEventListener('change', this.themeListener); } catch (_) {}
      this.themeHandler = null;
      this.themeListener = null;
    }
    var self = this;
    if (normalized === 'auto' && root.matchMedia && typeof root.matchMedia === 'function') {
      try {
        this.themeHandler = root.matchMedia('(prefers-color-scheme: dark)');
        this.themeListener = function () {
          if (self.destroyed) return;
          self.root.setAttribute('data-resolved-theme', self.resolvedTheme());
          if (typeof self.options.onThemeChange === 'function') {
            self.options.onThemeChange(self.resolvedTheme());
          }
        };
        this.themeHandler.addEventListener('change', this.themeListener);
      } catch (_) {
        this.themeHandler = null;
        this.themeListener = null;
      }
    }
    if (this.themeReady && previous !== this.resolvedTheme() && typeof this.options.onThemeChange === 'function') {
      this.options.onThemeChange(this.resolvedTheme());
    }
    return this;
  };

  Widget.prototype.isCodeType = function () {
    return this.options.type === 'sms' || this.options.type === 'email';
  };

  Widget.prototype.renderChallenge = function () {
    var challenge = this.challenge;
    if (!challenge) return;
    this.promptEl.textContent = challenge.prompt && challenge.prompt.text ? challenge.prompt.text : '';
    this.hintEl.textContent = challenge.prompt && challenge.prompt.hint ? challenge.prompt.hint : '';
    var render = this['render_' + challenge.type];
    if (typeof render !== 'function') {
      this.setStatus(this.labels.unsupported, 'error');
      return;
    }
    render.call(this, challenge);
    this.addRefresh();
  };

  Widget.prototype.addRefresh = function () {
    var self = this;
    var button = make('button', 'yd-captcha__button', this.labels.refresh);
    button.type = 'button';
    this.bind(button, 'click', function () { self.start(); });
    this.actionsEl.appendChild(button);
  };

  Widget.prototype.addSubmit = function (answer, pow) {
    var self = this;
    var button = make('button', 'yd-captcha__button yd-captcha__button--primary', this.labels.submit);
    button.type = 'button';
    this.bind(button, 'click', function () { self.submit(answer(), pow); });
    this.actionsEl.appendChild(button);
    return button;
  };

  Widget.prototype.submit = function (answer, pow) {
    var self = this;
    var challenge = this.challenge;
    if (this.busy || !challenge || this.blockedByCapture) return Promise.resolve();
    this.busy = true;
    this.setStatus(this.labels.verifying);
    var proofPromise = pow ? solvePoW(pow) : Promise.resolve(null);
    return proofPromise.then(function (proof) {
      // The user may refresh or fall back while PoW is running; never submit
      // an old answer against a new challenge. | PoW 期间可能刷新或降级；
      // 不得把旧答案提交到新挑战。
      if (self.destroyed || self.challenge !== challenge) return null;
      return self.request('verify', {
        id: challenge.id,
        answer: answer,
        signals: collectSignals(self.tracker, self.captureState),
        pow: proof || undefined
      });
    }).then(function (data) {
      if (!data) return;
      self.disable();
      self.setStatus(self.labels.success, 'success');
      if (typeof self.options.onSuccess === 'function') {
        self.options.onSuccess(data.result.token, data.result);
      }
    }).catch(function (err) {
      self.busy = false;
      if (self.answerReset && !(err && err.name === 'AbortError')) self.answerReset();
      self.handleError(err);
    });
  };

  Widget.prototype.disable = function () {
    var buttons = this.root.querySelectorAll('button, input, select');
    for (var i = 0; i < buttons.length; i++) buttons[i].disabled = true;
  };

  Widget.prototype.handleError = function (err) {
    if (this.destroyed || (err && err.name === 'AbortError')) return;
    this.busy = false;
    var message = err && err.message ? err.message : this.labels.network;
    if (err && err.retryAfter) message += ' (' + err.retryAfter + 's)';
    this.setStatus(message, 'error');
    if (typeof this.options.onError === 'function') this.options.onError(err);
  };

  Widget.prototype.imageURL = function (image) {
    return joinURL(this.options.endpoint, image.url);
  };

  Widget.prototype.imageByRole = function (name) {
    var images = this.challenge ? this.challenge.images || [] : [];
    for (var i = 0; i < images.length; i++) {
      if (images[i].name === name) return images[i];
    }
    return images.length ? images[0] : null;
  };

  Widget.prototype.loadImage = function (image) {
    var self = this;
    return new Promise(function (resolve, reject) {
      var img = new root.Image();
      img.onload = function () { resolve(img); };
      img.onerror = function () { reject(new Error('image load failed | 图片加载失败')); };
      img.crossOrigin = 'anonymous';
      img.src = self.imageURL(image);
    });
  };

  Widget.prototype.stagePoint = function (event, image) {
    var target = event && event.currentTarget && event.currentTarget.getBoundingClientRect ? event.currentTarget : this.stageEl;
    var rect = target.getBoundingClientRect();
    var imageWidth = image.width || rect.width;
    var imageHeight = image.height || rect.height;
    var x = (event.clientX - rect.left) * imageWidth / rect.width;
    var y = (event.clientY - rect.top) * imageHeight / rect.height;
    return {
      x: Math.max(0, Math.min(imageWidth, Math.round(x))),
      y: Math.max(0, Math.min(imageHeight, Math.round(y)))
    };
  };

  Widget.prototype.render_text = function (challenge) {
    var self = this;
    var image = this.imageByRole('challenge');
    if (!image) return this.setStatus(this.labels.network, 'error');
    var img = make('img', 'yd-captcha__image');
    img.alt = 'captcha';
    img.src = this.imageURL(image);
    this.stageEl.appendChild(img);
    this.bindPointer(img, {
      down: function (event) {
        var point = self.stagePoint(event, image);
        self.tracker.add('down', point.x, point.y);
      },
      move: function (event) {
        var point = self.stagePoint(event, image);
        self.tracker.add('move', point.x, point.y);
      },
      up: function (event) {
        var point = self.stagePoint(event, image);
        self.tracker.add('up', point.x, point.y);
      }
    });
    var input = make('input', 'yd-captcha__input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.autocapitalize = 'off';
    input.spellcheck = false;
    input.setAttribute('aria-label', challenge.prompt.hint || 'captcha answer');
    this.stageEl.appendChild(input);
    var button = this.addSubmit(function () { return { text: input.value, track: self.tracker.track() }; }, challenge.pow);
    this.bind(input, 'keydown', function (event) {
      if (event.key === 'Enter') { event.preventDefault(); button.click(); }
    });
    input.focus();
  };

  Widget.prototype.render_click = function (challenge, semantic) {
    var self = this;
    var image = this.imageByRole('challenge');
    if (!image) return this.setStatus(this.labels.network, 'error');
    var stage = make('div', 'yd-captcha__clickstage');
    var img = make('img', 'yd-captcha__image');
    img.alt = 'captcha';
    img.src = this.imageURL(image);
    var overlay = make('div', 'yd-captcha__overlay');
    stage.appendChild(img);
    stage.appendChild(overlay);
    this.stageEl.appendChild(stage);
    var points = [];
    var expected = challenge.prompt && challenge.prompt.count ? challenge.prompt.count : (semantic ? 2 : 3);
    // A failed verification must not leave old clicks in the next attempt. | 校验失败后不能把旧点击带入下一次尝试。
    this.answerReset = function () {
      points.length = 0;
      overlay.innerHTML = '';
    };
    this.bindPointer(stage, {
      down: function (event) {
        if (self.busy) return;
        if (event.preventDefault) event.preventDefault();
        var point = self.stagePoint(event, image);
        self.tracker.add('click', point.x, point.y);
        points.push(point);
        var marker = make('span', 'yd-captcha__marker', String(points.length));
        marker.style.left = (point.x * 100 / image.width) + '%';
        marker.style.top = (point.y * 100 / image.height) + '%';
        overlay.appendChild(marker);
        if (points.length >= expected) {
          self.submit({ points: points.slice(0), track: self.tracker.track() }, challenge.pow);
        }
      }
    });
  };

  Widget.prototype.render_click_text = function (challenge) { this.render_click(challenge, false); };
  Widget.prototype.render_click_icon = function (challenge) { this.render_click(challenge, false); };
  Widget.prototype.render_semantic = function (challenge) { this.render_click(challenge, true); };

  Widget.prototype.render_slide = function (challenge) {
    var self = this;
    var background = this.imageByRole('challenge');
    var pieceImage = this.imageByRole('piece');
    if (!background || !pieceImage) return this.setStatus(this.labels.network, 'error');
    var stage = make('div', 'yd-captcha__slidestage');
    var img = make('img', 'yd-captcha__image');
    img.alt = 'captcha';
    img.src = this.imageURL(background);
    var piece = make('img', 'yd-captcha__piece');
    piece.alt = '';
    piece.src = this.imageURL(pieceImage);
    piece.style.width = (pieceImage.width * 100 / background.width) + '%';
    stage.appendChild(img);
    stage.appendChild(piece);
    this.stageEl.appendChild(stage);
    var left = 0;
    var top = 0;
    var dragging = false;
    var startX = 0;
    var startY = 0;
    var baseLeft = 0;
    var baseTop = 0;
    function paint() {
      piece.style.left = (left * 100 / background.width) + '%';
      piece.style.top = (top * 100 / background.height) + '%';
    }
    function finish() {
      if (!dragging || self.busy) return;
      dragging = false;
      self.tracker.add('up', left, top);
      self.submit({ offset: Math.round(left), offset_y: Math.round(top), track: self.tracker.track() }, challenge.pow);
    }
    this.bindPointer(piece, {
      down: function (event) {
        if (self.busy) return;
        if (event.preventDefault) event.preventDefault();
        dragging = true;
        startX = event.clientX;
        startY = event.clientY;
        baseLeft = left;
        baseTop = top;
        if (piece.setPointerCapture && event.pointerId !== undefined) piece.setPointerCapture(event.pointerId);
        self.tracker.add('down', left, top);
      },
      move: function (event) {
        if (!dragging || self.busy) return;
        var rect = stage.getBoundingClientRect();
        var dx = (event.clientX - startX) * background.width / rect.width;
        var dy = (event.clientY - startY) * background.height / rect.height;
        left = Math.max(0, Math.min(background.width - pieceImage.width, baseLeft + dx));
        top = Math.max(0, Math.min(background.height - pieceImage.height, baseTop + dy));
        paint();
        self.tracker.add('move', left, top);
      },
      up: finish,
      cancel: function () { dragging = false; }
    });
    paint();
  };

  Widget.prototype.render_scratch = function (challenge) {
    var self = this;
    var baseImage = this.imageByRole('challenge');
    var coverImage = this.imageByRole('cover');
    if (!baseImage || !coverImage) return this.setStatus(this.labels.network, 'error');
    var stage = make('div', 'yd-captcha__scratchstage');
    var base = make('canvas', 'yd-captcha__canvas');
    var cover = make('canvas', 'yd-captcha__canvas yd-captcha__cover');
    base.width = baseImage.width;
    base.height = baseImage.height;
    cover.width = coverImage.width;
    cover.height = coverImage.height;
    stage.appendChild(base);
    stage.appendChild(cover);
    this.stageEl.appendChild(stage);
    var baseCtx = base.getContext('2d');
    var coverCtx = cover.getContext('2d');
    var ready = 0;
    function maybeReady() {
      ready++;
      if (ready === 2) {
        self.loadImage(baseImage).then(function (img) { baseCtx.drawImage(img, 0, 0); }).catch(function () {});
        self.loadImage(coverImage).then(function (img) { coverCtx.globalCompositeOperation = 'source-over'; coverCtx.drawImage(img, 0, 0); }).catch(function () {});
      }
    }
    maybeReady();
    maybeReady();
    var drawing = false;
    function scratch(event) {
      var point = self.stagePoint(event, baseImage);
      coverCtx.globalCompositeOperation = 'destination-out';
      coverCtx.beginPath();
      coverCtx.arc(point.x, point.y, Math.max(12, baseImage.width / 20), 0, Math.PI * 2);
      coverCtx.fill();
      self.tracker.add('scratch', point.x, point.y);
    }
    this.bindPointer(cover, {
      down: function (event) {
        if (event.preventDefault) event.preventDefault();
        drawing = true;
        scratch(event);
        if (cover.setPointerCapture && event.pointerId !== undefined) cover.setPointerCapture(event.pointerId);
      },
      move: function (event) { if (drawing) scratch(event); },
      up: function () { drawing = false; }
    });
    var input = make('input', 'yd-captcha__input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.placeholder = this.labels.scratch;
    input.setAttribute('aria-label', this.labels.scratch);
    this.stageEl.appendChild(input);
    this.addSubmit(function () {
      return { text: input.value, track: self.tracker.track() };
    }, challenge.pow);
  };

  Widget.prototype.render_rotate = function (challenge) {
    var self = this;
    var image = this.imageByRole('challenge');
    if (!image) return this.setStatus(this.labels.network, 'error');
    var stage = make('div', 'yd-captcha__rotatestage');
    var img = make('img', 'yd-captcha__image yd-captcha__rotating');
    img.alt = 'captcha';
    img.src = this.imageURL(image);
    stage.appendChild(img);
    this.stageEl.appendChild(stage);
    var range = make('input', 'yd-captcha__range');
    range.type = 'range';
    range.min = '0';
    range.max = '359';
    range.value = '0';
    range.setAttribute('aria-label', this.labels.rotateHint);
    this.stageEl.appendChild(range);
    var angle = 0;
    this.bind(range, 'input', function () {
      angle = Number(range.value || 0);
      img.style.transform = 'rotate(' + angle + 'deg)';
      self.tracker.add('rotate', angle, 0);
    });
    this.addSubmit(function () { return { angle: angle, track: self.tracker.track() }; }, challenge.pow);
  };

  Widget.prototype.renderCodeForm = function () {
    var self = this;
    this.clearStage();
    var channel = this.fallbackChannel || (this.options.type === 'email' ? 'email' : 'sms');
    this.promptEl.textContent = channel === 'email' ? this.labels.emailVerify : this.labels.smsVerify;
    this.hintEl.textContent = this.labels.code;
    if (this.fallbackActive && this.fallbackNotice) this.setNotice(this.fallbackNotice, 'warning');
    var target = make('input', 'yd-captcha__input');
    target.type = channel === 'email' ? 'email' : 'tel';
    target.autocomplete = channel === 'email' ? 'email' : 'tel';
    target.placeholder = channel === 'email' ? this.labels.targetEmail : this.labels.targetPhone;
    target.setAttribute('aria-label', target.placeholder);
    if (this.lastTarget) target.value = this.lastTarget;
    else if (this.options.target) target.value = this.options.target;
    var send = make('button', 'yd-captcha__button yd-captcha__button--primary', this.labels.send);
    send.type = 'button';
    this.stageEl.appendChild(target);
    this.actionsEl.appendChild(send);
    if (this.fallbackActive) {
      var back = make('button', 'yd-captcha__button', this.labels.backToImage);
      back.type = 'button';
      this.bind(back, 'click', function () { self.start(); });
      this.actionsEl.appendChild(back);
    }
    this.bind(send, 'click', function () {
      if (self.busy) return;
      self.lastTarget = target.value;
      self.busy = true;
      self.setStatus(self.labels.loading);
      self.request('send', {
        channel: channel,
        target: target.value,
        action: self.options.action,
        locale: self.options.locale,
        signals: collectSignals(self.tracker, self.captureState),
        fallback: !!self.fallbackActive,
        capture_kind: self.fallbackActive ? self.fallbackKind : undefined
      }).then(function (data) {
        self.challenge = data.challenge;
        self.busy = false;
        self.renderCodeVerify();
      }).catch(function (err) {
        self.busy = false;
        self.handleError(err);
      });
    });
  };

  Widget.prototype.renderCodeVerify = function () {
    var self = this;
    this.clearStage();
    this.promptEl.textContent = this.challenge.prompt ? this.challenge.prompt.text : this.labels.code;
    this.hintEl.textContent = this.challenge.target ? this.challenge.target : '';
    var notice = this.challenge.notice || (this.fallbackActive ? this.fallbackNotice : '');
    if (notice) this.setNotice(notice, 'warning');
    var code = make('input', 'yd-captcha__input');
    code.type = 'text';
    code.inputMode = 'numeric';
    code.autocomplete = 'one-time-code';
    code.maxLength = 6;
    code.placeholder = this.labels.code;
    code.setAttribute('aria-label', this.labels.code);
    this.stageEl.appendChild(code);
    var button = this.addSubmit(function () { return { code: code.value }; }, null);
    this.bind(code, 'keydown', function (event) {
      if (event.key === 'Enter') { event.preventDefault(); button.click(); }
    });
    var resend = make('button', 'yd-captcha__button', this.labels.resend);
    resend.type = 'button';
    this.bind(resend, 'click', function () { self.renderCodeForm(); });
    this.actionsEl.appendChild(resend);
    if (this.fallbackActive) {
      var back = make('button', 'yd-captcha__button', this.labels.backToImage);
      back.type = 'button';
      this.bind(back, 'click', function () { self.start(); });
      this.actionsEl.appendChild(back);
    }
    code.focus();
  };

  Widget.prototype.sendCode = function () {
    if (!this.isCodeType()) return Promise.resolve();
    this.renderCodeForm();
    var send = this.actionsEl.querySelector('button');
    if (send) send.click();
    return Promise.resolve();
  };

  return {
    version: VERSION,
    mount: function (target, options) { return new Widget(target, options); },
    locales: Object.keys(LABELS_CATALOG).sort(),
    labels: function (locale, custom) { return labelsFor({ locale: locale, labels: custom }); },
    solvePoW: solvePoW,
    _normalizeLocale: normalizeLocale,
    _normalizeTheme: normalizeTheme,
    _labels: labelsFor,
    _sha256: sha256Bytes,
    _leadingZeroBits: leadingZeroBits,
    _screenshotShortcut: screenshotShortcut
  };
});
