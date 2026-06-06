// netlify/functions/save-content.js
// Securely saves content.json changes to GitHub via the GitHub API.
// Required environment variables (set in Netlify dashboard):
//   ADMIN_PASSWORD  – the password Tonia uses to log into admin.html
//   GITHUB_PAT      – a GitHub Personal Access Token with "repo" scope
//   GITHUB_REPO     – e.g. "username/apartment-antonia"
//   GITHUB_BRANCH   – branch to commit to, e.g. "main" (defaults to "main")

const https = require('https');
const crypto = require('crypto');

// ── Security: In-memory brute-force rate limiter ─────────────────────────────
// NOTE: Serverless functions can have multiple instances, so this works as
// a "best effort" rate limiter per instance. It's enough to slow down most
// automated attacks. For a full solution, a distributed store (Redis) is needed.

const failedAttempts = new Map(); // IP -> { count, firstAttempt }
const MAX_ATTEMPTS = 5;           // Max allowed failures
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minute lockout window
const FAILURE_DELAY_MS = 500;     // Base delay on each failed attempt (ms)

function getClientIP(event) {
  return (
    event.headers['x-forwarded-for']?.split(',')[0].trim() ||
    event.headers['x-nf-client-connection-ip'] ||
    event.headers['client-ip'] ||
    'unknown'
  );
}

function isRateLimited(ip) {
  const record = failedAttempts.get(ip);
  if (!record) return false;

  const now = Date.now();
  // Reset if the lockout window has passed
  if (now - record.firstAttempt > LOCKOUT_WINDOW_MS) {
    failedAttempts.delete(ip);
    return false;
  }

  return record.count >= MAX_ATTEMPTS;
}

function recordFailure(ip) {
  const now = Date.now();
  const record = failedAttempts.get(ip);

  if (!record || (now - record.firstAttempt > LOCKOUT_WINDOW_MS)) {
    failedAttempts.set(ip, { count: 1, firstAttempt: now });
  } else {
    record.count += 1;
  }
}

function clearFailures(ip) {
  failedAttempts.delete(ip);
}

// ── Security: Timing-safe string comparison ───────────────────────────────────
// Prevents timing attacks where an attacker can measure response time to guess
// characters of the password one by one.
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // Both must be the same length for timingSafeEqual
  const aHash = crypto.createHash('sha256').update(a).digest();
  const bHash = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(aHash, bHash);
}

// ── Security: Validate and sanitize incoming content ─────────────────────────
function isValidContent(content) {
  if (!content || typeof content !== 'object' || Array.isArray(content)) return false;

  // Required top-level keys
  const required = ['translations', 'pricePerNight', 'minNights', 'contactWhatsApp', 'contactEmail', 'reviews', 'gallery'];
  for (const key of required) {
    if (!(key in content)) return false;
  }

  // Type checks
  if (typeof content.pricePerNight !== 'number' || content.pricePerNight < 1 || content.pricePerNight > 10000) return false;
  if (typeof content.minNights !== 'number' || content.minNights < 1 || content.minNights > 365) return false;
  if (typeof content.contactWhatsApp !== 'string' || !/^\d{7,15}$/.test(content.contactWhatsApp)) return false;
  if (typeof content.contactEmail !== 'string' || content.contactEmail.length > 200) return false;
  if (!Array.isArray(content.reviews) || content.reviews.length > 100) return false;
  if (!Array.isArray(content.gallery) || content.gallery.length > 200) return false;
  if (typeof content.translations !== 'object') return false;

  return true;
}

// ── Security: Validate uploaded images ───────────────────────────────────────
function isValidImageUpload(upload) {
  if (!upload || typeof upload !== 'object') return false;
  if (typeof upload.filename !== 'string' || upload.filename.length === 0 || upload.filename.length > 100) return false;
  if (typeof upload.base64 !== 'string' || upload.base64.length === 0) return false;

  // Only allow safe image extensions
  const allowedExts = /\.(jpg|jpeg|png|webp|gif)$/i;
  if (!allowedExts.test(upload.filename)) return false;

  return true;
}

// ── Standard CORS and security response headers ───────────────────────────────
const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store',
};

// ── Tiny GitHub API helper ──────────────────────────────────────────────────

function githubRequest(method, path, body, pat) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        'Authorization': `token ${pat}`,
        'User-Agent': 'ApartmentAntonia-Admin/1.0',
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {})
      }
    };

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', chunk => responseBody += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(responseBody) });
        } catch {
          resolve({ status: res.statusCode, body: responseBody });
        }
      });
    });

    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ── Main Handler ─────────────────────────────────────────────────────────────

exports.handler = async function (event) {
  // ── Only allow POST ────────────────────────────────────────────────────────
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: SECURITY_HEADERS, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  // ── Enforce JSON content type ─────────────────────────────────────────────
  const contentType = event.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return { statusCode: 415, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Unsupported Media Type: expected application/json' }) };
  }

  // ── Rate limiting check ───────────────────────────────────────────────────
  const clientIP = getClientIP(event);
  if (isRateLimited(clientIP)) {
    console.warn(`Rate limit exceeded for IP: ${clientIP}`);
    // Add artificial delay to further discourage brute forcing
    await new Promise(r => setTimeout(r, 2000));
    return {
      statusCode: 429,
      headers: { ...SECURITY_HEADERS, 'Retry-After': '900' },
      body: JSON.stringify({ error: 'Too many requests. Please try again in 15 minutes.' })
    };
  }

  // ── Parse request body ────────────────────────────────────────────────────
  let payload;
  try {
    if (!event.body || event.body.length > 50 * 1024 * 1024) { // 50MB max
      throw new Error('Body too large or empty');
    }
    payload = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Invalid or oversized request body' }) };
  }

  // ── Extract and validate password field ──────────────────────────────────
  const { password } = payload;

  if (typeof password !== 'string' || password.length === 0 || password.length > 200) {
    await new Promise(r => setTimeout(r, FAILURE_DELAY_MS));
    return { statusCode: 400, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Invalid request: missing password' }) };
  }

  // ── 1. Validate password ──────────────────────────────────────────────────
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (!ADMIN_PASSWORD) {
    console.error('ADMIN_PASSWORD environment variable is not set.');
    return { statusCode: 500, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Server misconfiguration' }) };
  }

  if (!safeCompare(password, ADMIN_PASSWORD)) {
    recordFailure(clientIP);
    const attempts = failedAttempts.get(clientIP)?.count || 1;
    const remaining = Math.max(0, MAX_ATTEMPTS - attempts);

    // Progressive delay: each failed attempt is slower
    await new Promise(r => setTimeout(r, FAILURE_DELAY_MS * attempts));

    console.warn(`Failed login attempt from ${clientIP} (attempt ${attempts}/${MAX_ATTEMPTS})`);
    return {
      statusCode: 401,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({
        error: 'Unauthorized: incorrect password',
        ...(remaining > 0
          ? { hint: `${remaining} pokušaja preostalo prije zaključavanja` }
          : { hint: 'Previše neuspješnih pokušaja. Pokušajte za 15 minuta.' })
      })
    };
  }

  // ── Password is correct — clear any failure record ────────────────────────
  clearFailures(clientIP);

  // ── If this is just a login validation (dry run) ──────────────────────────
  if (payload.dryRun === true) {
    return {
      statusCode: 200,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ success: true, message: 'Password verified' })
    };
  }

  // ── 2. Validate the content payload ──────────────────────────────────────
  const { content } = payload;
  if (!isValidContent(content)) {
    return {
      statusCode: 400,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ error: 'Invalid content structure. Refresh and try again.' })
    };
  }

  // ── 3. Read environment config ────────────────────────────────────────────
  const PAT    = process.env.GITHUB_PAT;
  const REPO   = process.env.GITHUB_REPO;
  const BRANCH = process.env.GITHUB_BRANCH || 'main';

  if (!PAT || !REPO) {
    console.error('GITHUB_PAT or GITHUB_REPO environment variable is not set.');
    return { statusCode: 500, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Server misconfiguration: missing GitHub credentials' }) };
  }

  // ── 4. Extract and validate any pending image uploads ────────────────────
  const uploads = Array.isArray(content._uploads) ? content._uploads : [];
  delete content._uploads;

  const errors = [];
  const uploaded = [];

  // ── 5. Commit each uploaded image to images/ directory ────────────────────
  for (const upload of uploads) {
    if (!isValidImageUpload(upload)) {
      errors.push(`Skipped invalid upload: ${upload?.filename || 'unnamed'}`);
      continue;
    }

    const safeFilename = upload.filename
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g, '_')
      .replace(/_{2,}/g, '_'); // Collapse multiple underscores
    const filePath = `/repos/${REPO}/contents/images/${safeFilename}`;

    try {
      const existing = await githubRequest('GET', filePath, null, PAT);
      const existingSha = existing.status === 200 ? existing.body.sha : undefined;

      const base64Data = upload.base64.includes(',')
        ? upload.base64.split(',')[1]
        : upload.base64;

      const commitBody = {
        message: `Admin: upload image ${safeFilename}`,
        content: base64Data,
        branch: BRANCH,
        ...(existingSha ? { sha: existingSha } : {})
      };

      const result = await githubRequest('PUT', filePath, commitBody, PAT);

      if (result.status === 200 || result.status === 201) {
        uploaded.push(safeFilename);
      } else {
        console.error(`Failed to upload ${safeFilename}:`, result.body);
        errors.push(`Image upload failed for ${safeFilename}: ${result.body.message || 'Unknown error'}`);
      }
    } catch (err) {
      console.error(`Error uploading ${upload.filename}:`, err);
      errors.push(`Image upload error for ${upload.filename}: ${err.message}`);
    }
  }

  // ── 6. Commit updated content.json ───────────────────────────────────────
  const contentPath = `/repos/${REPO}/contents/content.json`;

  try {
    const currentFile = await githubRequest('GET', contentPath, null, PAT);

    if (currentFile.status !== 200) {
      return {
        statusCode: 500,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({ error: `Could not fetch content.json from GitHub: ${currentFile.body.message || 'Not found'}` })
      };
    }

    const currentSha = currentFile.body.sha;
    const contentString = JSON.stringify(content, null, 2);
    const contentBase64 = Buffer.from(contentString, 'utf8').toString('base64');

    const commitBody = {
      message: 'Admin: update content.json via dashboard',
      content: contentBase64,
      sha: currentSha,
      branch: BRANCH
    };

    const commitResult = await githubRequest('PUT', contentPath, commitBody, PAT);

    if (commitResult.status === 200 || commitResult.status === 201) {
      return {
        statusCode: 200,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({
          success: true,
          message: 'Content saved and site redeploy triggered.',
          uploadedImages: uploaded,
          warnings: errors.length ? errors : undefined
        })
      };
    } else {
      console.error('GitHub commit failed:', commitResult.body);
      return {
        statusCode: 500,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({
          error: `GitHub commit failed: ${commitResult.body.message || 'Unknown error'}`,
          uploadedImages: uploaded
        })
      };
    }
  } catch (err) {
    console.error('Fatal error in save-content function:', err);
    return {
      statusCode: 500,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ error: 'Internal server error' }) // Never expose err.message in prod
    };
  }
};
