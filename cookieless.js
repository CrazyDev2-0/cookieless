// Generate Token
async function generateToken() {
    const canvasFingerprint = await getCanvasFingerprint();
    const webglFingerprint = await getWebGLFingerprint();
    const metadata = await getMetadata();
    const audioFingerprint = await getAudioFingerprint();
    const availableFonts = await getFontMetadata();
    const payload = JSON.stringify({
        canvasFingerprint: canvasFingerprint,
        webglFingerprint: webglFingerprint,
        metadata: metadata,
        audioFingerprint: audioFingerprint,
        fonts: availableFonts
    });
    return await sha256(payload);
}

// Generate hash
async function sha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);
    // hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // convert bytes to hex string
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate Canvas Fingerprint
async function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    canvas.width = 300;
    canvas.height = 150;
    const ctx = canvas.getContext('2d');
    const txt1 = '@$%&*aBcDeFgHiJkLmNoPqRsTuVwXyZ';
    const txt2 = '@$%&*AbCdEfGhIjKlMnOpQrStUvWxYz';

    // Draw rectangle - Layer 1
    ctx.fillStyle = "rgb(241,44,44)";
    ctx.fillRect(0, 0, 300, 150);

    // Draw rectangle - Layer 2
    ctx.fillStyle = "rgba(12,254,234,0.76)";
    ctx.fillRect(40, 10, 50, 130);

    // Draw rectangle - Layer 3
    ctx.fillStyle = "rgba(65,255,0,0.62)";
    ctx.fillRect(20, 55, 260, 40);

    // Draw text - Layer 4
    ctx.fillStyle = "#5100cc";
    ctx.font = "bold 17px 'Arial'";
    ctx.shadowColor = "white";
    ctx.shadowBlur = 5;
    ctx.textBaseline = "top";
    ctx.rotate(15 * Math.PI / 180);
    ctx.borderWidth = 5;
    ctx.borderColor = "#dc02fd";
    ctx.strokeText(txt1, 32, 25);
    ctx.fillText(txt1, 30, 23);
    ctx.rotate(-15 * Math.PI / 180);
    ctx.shadowBlur = 0;
    ctx.borderWidth = 2;

    // Draw circle - Layer 5
    ctx.beginPath();
    ctx.arc(200, 75, 55, 0, 2 * Math.PI);
    ctx.fillStyle = "rgba(169,117,199,0.88)"
    ctx.fill()
    ctx.strokeStyle = "#b300ff"
    ctx.stroke()

    // Draw text - Layer 6
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 17px 'Arial'";
    ctx.shadowColor = "black";
    ctx.shadowBlur = 7;
    ctx.textBaseline = "alphabetic";
    ctx.rotate(-15 * Math.PI / 180);
    ctx.fillText(txt2, 16, 125);
    ctx.rotate(15 * Math.PI / 180);

    // Draw rectangle - Layer 7
    ctx.rotate(10 * Math.PI / 180);
    ctx.strokeStyle = "rgba(255,0,0,0.62)";
    ctx.lineWidth = 5;
    ctx.strokeRect(80, 40, 150, 20);
    ctx.rotate(-10 * Math.PI / 180);

    // Draw rectangle - Layer 8
    ctx.rotate(-10 * Math.PI / 180);
    ctx.strokeStyle = "rgba(0,0,255,0.62)";
    ctx.lineWidth = 5;
    ctx.strokeRect(45, 120, 170, 20);
    ctx.rotate(10 * Math.PI / 180);

    return canvas.toDataURL();
}

// Generate WebGL Fingerprint
let vertexShaderSource = `
      #version 100
      precision highp float;
      attribute vec2 position;
      void main() {
        gl_Position = vec4(position, 0.0, 1.0);
        gl_PointSize = 128.0;
      }`

let fragmentShaderSource = `
      #version 100
      precision mediump float;
      void main() {
        vec2 fragmentPosition = 2.0*gl_PointCoord - 1.0;
        float distance = length(fragmentPosition);
        float distanceSqrd = distance * distance;
        gl_FragColor = vec4(
          0.2/distanceSqrd,
          0.1/distanceSqrd,
          0.0, 1.0 );
      }
    `

async function getWebGLFingerprint() {
    let buffer;
    let gl;
    let program;

    const canvasElement = document.createElement("canvas");
    canvasElement.width = 100;
    canvasElement.height = 100;
    gl = canvasElement.getContext("webgl") || canvasElement.getContext("experimental-webgl");

    if (!gl) {
        return null;
    }
    gl.viewport(0, 0, gl.drawingBufferWidth, gl.drawingBufferHeight);
    gl.clearColor(0.0, 0.0, 0.0, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);

    const vertexShader = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vertexShader, vertexShaderSource);
    gl.compileShader(vertexShader);

    const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fragmentShader, fragmentShaderSource);
    gl.compileShader(fragmentShader);

    program = gl.createProgram();
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    gl.detachShader(program, vertexShader);
    gl.detachShader(program, fragmentShader);
    gl.deleteShader(vertexShader);
    gl.deleteShader(fragmentShader);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        // cleanup
        gl.useProgram(null);
        if (buffer) {
            gl.deleteBuffer(buffer);
        }
        if (program) {
            gl.deleteProgram(program);
        }
        return null;
    }
    // Initialize Attributes
    gl.enableVertexAttribArray(0);
    buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
        gl.ARRAY_BUFFER,
        new Float32Array([0.0, 0.0]),
        gl.STATIC_DRAW,
    );
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

    gl.useProgram(program);
    gl.drawArrays(gl.POINTS, 0, 1);

    // print fingerprint
    const dataURL = canvasElement.toDataURL();

    // cleanup
    gl.useProgram(null);
    if (buffer) {
        gl.deleteBuffer(buffer);
    }
    if (program) {
        gl.deleteProgram(program);
    }

    return dataURL;
}

// Generate Audio Fingerprint
async function getAudioFingerprint() {
    const AudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    const context = new AudioContext(1, 5000, 44100);

    const compressor = context.createDynamicsCompressor()
    compressor.threshold.value = -50
    compressor.knee.value = 40
    compressor.ratio.value = 12
    compressor.reduction.value = 20
    compressor.attack.value = 0
    compressor.release.value = 0.2

    const oscillator = context.createOscillator()
    oscillator.type = "triangle"
    oscillator.frequency.value = 1000

    oscillator.connect(compressor)
    compressor.connect(context.destination);

    oscillator.start()
    let audioRenderedBuffer = await context.startRendering()
    let samples = audioRenderedBuffer.getChannelData(0)

    function calculateHash(samples) {
        let hash = 0
        for (let i = 0; i < samples.length; ++i) {
            hash += Math.abs(samples[i])
        }
        return hash
    }

    return calculateHash(samples)
}

// Generate Metadata
async function getMetadata() {
    let metadata = {};
    // Color depth
    metadata.colorDepth = window.screen.colorDepth;
    // Color Gamut
    function fetchColorGamut() {
        if (matchMedia('(color-gamut: rec2020)').matches)
            return 'rec2020';
        if (matchMedia('(color-gamut: p3)').matches)
            return 'p3';
        if (matchMedia('(color-gamut: srgb)').matches)
            return 'srgb';
        return 'unknown';
    }
    metadata.colorGamut = fetchColorGamut();
    // Screen resolution
    metadata.screenResolution = window.screen.width + "x" + window.screen.height;
    // Touch support
    function fetchMaxTouchPoints() {
        let touchPoints = 0;
        if (navigator.maxTouchPoints) {
            touchPoints = navigator.maxTouchPoints;
        } else if (navigator.msMaxTouchPoints) {
            touchPoints = navigator.msMaxTouchPoints;
        }
        return touchPoints;
    }
    function isTouchSupported() {
        try {
            document.createEvent("TouchEvent");
            return true;
        } catch {
            return false;
        }
    }
    metadata.maxTouchPoints = fetchMaxTouchPoints();
    metadata.touchSupport = isTouchSupported();
    // Screen HDR mode
    metadata.hdrMode = "unknown";
    if (window.matchMedia && window.matchMedia("(dynamic-range: high)").matches) {
        metadata.hdrMode = "high";
    } else if (window.matchMedia && window.matchMedia("(dynamic-range: standard)").matches) {
        metadata.hdrMode = "standard";
    }
    // Timezone
    if (window.Intl && typeof window.Intl.DateTimeFormat === 'function') {
        metadata.timeZone = window.Intl.DateTimeFormat().resolvedOptions().timeZone;
    } else {
        metadata.timeZone = 'unknown';
    }
    // Vendor
    metadata.vendor = navigator.vendor || "";
    // PDF Viewer Enabled
    metadata.pdfViewerEnabled = navigator.pdfViewerEnabled
    // Device Memory
    metadata.deviceMemory = -1.0;
    if (navigator.deviceMemory) {
        metadata.deviceMemory = navigator.deviceMemory;
    }
    // Session Storage check
    metadata.sessionStorageExists = false;
    try {
        metadata.sessionStorageExists = !!window.sessionStorage;
    } catch {
        metadata.sessionStorageExists = true;
    }
    // Local Storage check
    metadata.localStorageExists = false;
    try {
        metadata.localStorageExists = !!window.localStorage;
    } catch {
        metadata.localStorageExists = true;
    }
    // Math Values
    function fetchMathValues() {
        const defaultVal = () => 0;
        const acos = Math.acos || defaultVal;
        const acosh = Math.acosh || defaultVal;
        const asin = Math.asin || defaultVal;
        const asinh = Math.asinh || defaultVal;
        const atan = Math.atan || defaultVal;
        const atanh = Math.atanh || defaultVal;
        const atan2 = Math.atan2 || defaultVal;
        const cos = Math.cos || defaultVal;
        const cosh = Math.cosh || defaultVal;
        const sin = Math.sin || defaultVal;
        const sinh = Math.sinh || defaultVal;
        const tan = Math.tan || defaultVal;
        const tanh = Math.tanh || defaultVal;

        return {
            asin: asin(0.123456789012345),
            asinh: asinh(1.123456789012345),
            acos: acos(0.123456789012345),
            acosh: acosh(1.123456789012345),
            atan: atan(0.123456789012345),
            atanh: atanh(0.123456789012345),
            atan2: atan2(0.123456789012345, 1.123456789012345),
            cos: cos(0.123456789012345),
            cosh: cosh(1.123456789012345),
            sin: sin(0.123456789012345),
            sinh: sinh(1.123456789012345),
            tan: tan(0.123456789012345),
            tanh: tanh(1.123456789012345),
        };
    }
    metadata.mathValues = fetchMathValues();
    return metadata;
}

async function getFontMetadata() {
    const baseFonts = [
      // This is android-specific font from "Roboto" family
      'sans-serif-thin',
      'ARNO PRO',
      'Agency FB',
      'Arabic Typesetting',
      'Arial Unicode MS',
      'AvantGarde Bk BT',
      'BankGothic Md BT',
      'Batang',
      'Bitstream Vera Sans Mono',
      'Calibri',
      'Century',
      'Century Gothic',
      'Clarendon',
      'EUROSTILE',
      'Franklin Gothic',
      'Futura Bk BT',
      'Futura Md BT',
      'GOTHAM',
      'Gill Sans',
      'HELV',
      'Haettenschweiler',
      'Helvetica Neue',
      'Humanst521 BT',
      'Leelawadee',
      'Letter Gothic',
      'Levenim MT',
      'Lucida Bright',
      'Lucida Sans',
      'Menlo',
      'MS Mincho',
      'MS Outlook',
      'MS Reference Specialty',
      'MS UI Gothic',
      'MT Extra',
      'MYRIAD PRO',
      'Marlett',
      'Meiryo UI',
      'Microsoft Uighur',
      'Minion Pro',
      'Monotype Corsiva',
      'PMingLiU',
      'Pristina',
      'SCRIPTINA',
      'Segoe UI Light',
      'Serifa',
      'SimHei',
      'Small Fonts',
      'Staccato222 BT',
      'TRAJAN PRO',
      'Univers CE 55 Medium',
      'Vrinda',
      'ZWAdobeF',
    ]
    const testString = "mmwwwwWWlli@0OO&1";
    const testSize = '72px';

    let body = document.getElementsByTagName("body")[0];
    let h = document.createElement("div");
    // h.style.setProperty('visibility', 'hidden', 'important')
    let s = document.createElement("span");
    s.style.fontSize = testSize;
    s.innerHTML = testString;
    let defaultWidth = {};
    let defaultHeight = {};
    body.appendChild(h);
    for (let index in baseFonts) {
        //get the default width for the three base fonts
        s.style.fontFamily = baseFonts[index];
        h.appendChild(s);
        defaultWidth[baseFonts[index]] = s.offsetWidth; //width for the default font
        defaultHeight[baseFonts[index]] = s.offsetHeight; //height for the default font
        h.removeChild(s);
    }

    function detect(font) {
        let detected = false;
        for (let index in baseFonts) {
            s.style.fontFamily = font + ',' + baseFonts[index]; // name of the font along with the base font for fallback.
            h.appendChild(s);
            let matched = (s.offsetWidth !== defaultWidth[baseFonts[index]] || s.offsetHeight !== defaultHeight[baseFonts[index]]);
            h.removeChild(s);
            detected = detected || matched;
        }
        return detected;
    }

    const res = baseFonts.filter(detect);
    body.removeChild(h);
    return res;
}
