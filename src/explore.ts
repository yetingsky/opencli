/**
 * Deep Explore: intelligent API discovery with response analysis.
 *
 * Unlike simple page snapshots, Deep Explore intercepts network traffic,
 * analyzes response schemas, and automatically infers capabilities that
 * can be turned into CLI commands.
 *
 * Flow:
 *   1. Navigate to target URL
 *   2. Auto-scroll to trigger lazy loading
 *   3. Capture network requests (with body analysis)
 *   4. For each JSON response: detect list fields, infer columns, analyze auth
 *   5. Detect frontend framework (Vue/React/Pinia/Next.js)
 *   6. Generate structured capabilities.json
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { browserSession, DEFAULT_BROWSER_EXPLORE_TIMEOUT, runWithTimeout } from './runtime.js';

// ── Site name detection ────────────────────────────────────────────────────

const KNOWN_ALIASES: Record<string, string> = {
  'x.com': 'twitter', 'twitter.com': 'twitter',
  'news.ycombinator.com': 'hackernews',
  'www.zhihu.com': 'zhihu', 'www.bilibili.com': 'bilibili',
  'www.v2ex.com': 'v2ex', 'www.reddit.com': 'reddit',
  'www.xiaohongshu.com': 'xiaohongshu', 'www.douban.com': 'douban',
  'www.weibo.com': 'weibo', 'search.bilibili.com': 'bilibili',
};

function detectSiteName(url: string): string {
  try {
    const host = new URL(url).hostname.toLowerCase();
    if (host in KNOWN_ALIASES) return KNOWN_ALIASES[host];
    const parts = host.split('.').filter(p => p && p !== 'www');
    if (parts.length >= 2) {
      if (['uk', 'jp', 'cn', 'com'].includes(parts[parts.length - 1]) && parts.length >= 3) {
        return parts[parts.length - 3].replace(/[^a-z0-9]/g, '');
      }
      return parts[parts.length - 2].replace(/[^a-z0-9]/g, '');
    }
    return parts[0]?.replace(/[^a-z0-9]/g, '') ?? 'site';
  } catch { return 'site'; }
}

// ── Field & capability inference ───────────────────────────────────────────

/**
 * Common field names grouped by semantic role.
 * Used to auto-detect which response fields map to which columns.
 */
const FIELD_ROLES: Record<string, string[]> = {
  title:       ['title', 'name', 'text', 'content', 'desc', 'description', 'headline', 'subject'],
  url:         ['url', 'uri', 'link', 'href', 'permalink', 'jump_url', 'web_url', 'short_link', 'share_url'],
  author:      ['author', 'username', 'user_name', 'nickname', 'nick', 'owner', 'creator', 'up_name', 'uname'],
  score:       ['score', 'hot', 'heat', 'likes', 'like_count', 'view_count', 'views', 'stat', 'play', 'favorite_count', 'reply_count'],
  time:        ['time', 'created_at', 'publish_time', 'pub_time', 'date', 'ctime', 'mtime', 'pubdate', 'created'],
  id:          ['id', 'aid', 'bvid', 'mid', 'uid', 'oid', 'note_id', 'item_id'],
  cover:       ['cover', 'pic', 'image', 'thumbnail', 'poster', 'avatar'],
  category:    ['category', 'tag', 'type', 'tname', 'channel', 'section'],
};

/** Param names that indicate searchable APIs */
const SEARCH_PARAMS = new Set(['q', 'query', 'keyword', 'search', 'wd', 'kw', 'search_query', 'w']);
/** Param names that indicate pagination */
const PAGINATION_PARAMS = new Set(['page', 'pn', 'offset', 'cursor', 'next', 'page_num']);
/** Param names that indicate limit control */
const LIMIT_PARAMS = new Set(['limit', 'count', 'size', 'per_page', 'page_size', 'ps', 'num']);
/** Content types to ignore */
const IGNORED_CONTENT_TYPES = new Set(['image/', 'font/', 'text/css', 'text/javascript', 'application/javascript', 'application/wasm']);
/** Volatile query params to strip from patterns */
const VOLATILE_PARAMS = new Set(['w_rid', 'wts', '_', 'callback', 'timestamp', 't', 'nonce', 'sign']);

// ── Network analysis ───────────────────────────────────────────────────────

interface NetworkEntry {
  method: string;
  url: string;
  status: number | null;
  contentType: string;
  responseBody?: any;
  requestHeaders?: Record<string, string>;
  queryParams?: Record<string, string>;
}

interface AnalyzedEndpoint {
  pattern: string;
  method: string;
  url: string;
  status: number | null;
  contentType: string;
  queryParams: string[];
  hasSearchParam: boolean;
  hasPaginationParam: boolean;
  hasLimitParam: boolean;
  authIndicators: string[];
  responseAnalysis: ResponseAnalysis | null;
}

interface ResponseAnalysis {
  itemPath: string | null;
  itemCount: number;
  detectedFields: Record<string, string>;  // role → actual field name
  sampleFieldNames: string[];
}

interface InferredCapability {
  name: string;
  description: string;
  strategy: string;
  confidence: number;
  endpoint: string;
  itemPath: string | null;
  recommendedColumns: string[];
  recommendedArgs: Array<{ name: string; type: string; required: boolean; default?: any }>;
}

/**
 * Parse raw network output from Playwright MCP into structured entries.
 * Handles both text format ([GET] url => [200]) and structured JSON.
 */
function parseNetworkOutput(raw: any): NetworkEntry[] {
  if (typeof raw === 'string') {
    // Playwright MCP returns network as text lines like:
    // "[GET] https://api.example.com/xxx => [200] "
    // May also have markdown headers like "### Result"
    const entries: NetworkEntry[] = [];
    const lines = raw.split('\n').filter((l: string) => l.trim());
    for (const line of lines) {
      // Format: [METHOD] URL => [STATUS] optional_extra
      const bracketMatch = line.match(/^\[?(GET|POST|PUT|DELETE|PATCH|OPTIONS)\]?\s+(\S+)\s*(?:=>|→)\s*\[?(\d+)\]?/i);
      if (bracketMatch) {
        const [, method, url, status] = bracketMatch;
        entries.push({
          method: method.toUpperCase(),
          url,
          status: status ? parseInt(status) : null,
          contentType: url.endsWith('.json') ? 'application/json' :
                       (url.includes('/api/') || url.includes('/x/')) ? 'application/json' : '',
        });
        continue;
      }
      // Legacy format: GET url → 200 (application/json)
      const legacyMatch = line.match(/^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s*→?\s*(\d+)?\s*(?:\(([^)]*)\))?/i);
      if (legacyMatch) {
        const [, method, url, status, ct] = legacyMatch;
        entries.push({
          method: method.toUpperCase(),
          url,
          status: status ? parseInt(status) : null,
          contentType: ct ?? '',
        });
      }
    }
    return entries;
  }
  if (Array.isArray(raw)) {
    return raw.map((e: any) => ({
      method: (e.method ?? 'GET').toUpperCase(),
      url: e.url ?? e.request?.url ?? '',
      status: e.status ?? e.statusCode ?? null,
      contentType: e.contentType ?? e.mimeType ?? '',
      responseBody: e.responseBody ?? e.body,
      requestHeaders: e.requestHeaders ?? e.headers,
    }));
  }
  return [];
}



/**
 * Normalize a URL into a pattern by replacing IDs with placeholders.
 */
function urlToPattern(url: string): string {
  try {
    const parsed = new URL(url);
    const pathNorm = parsed.pathname
      .replace(/\/\d+/g, '/{id}')
      .replace(/\/[0-9a-fA-F]{8,}/g, '/{hex}')
      .replace(/\/BV[a-zA-Z0-9]{10}/g, '/{bvid}');
    const params: string[] = [];
    parsed.searchParams.forEach((_v, k) => {
      if (!VOLATILE_PARAMS.has(k)) params.push(k);
    });
    const qs = params.length ? '?' + params.sort().map(k => `${k}={}`).join('&') : '';
    return `${parsed.host}${pathNorm}${qs}`;
  } catch { return url; }
}

/**
 * Extract query params from a URL.
 */
function extractQueryParams(url: string): Record<string, string> {
  try {
    const params: Record<string, string> = {};
    new URL(url).searchParams.forEach((v, k) => { params[k] = v; });
    return params;
  } catch { return {}; }
}

/**
 * Detect auth indicators from request headers.
 */
function detectAuthIndicators(headers?: Record<string, string>): string[] {
  if (!headers) return [];
  const indicators: string[] = [];
  const keys = Object.keys(headers).map(k => k.toLowerCase());
  if (keys.some(k => k === 'authorization')) indicators.push('bearer');
  if (keys.some(k => k.startsWith('x-csrf') || k.startsWith('x-xsrf'))) indicators.push('csrf');
  if (keys.some(k => k.startsWith('x-s') || k === 'x-t' || k === 'x-s-common')) indicators.push('signature');
  if (keys.some(k => k === 'x-client-transaction-id')) indicators.push('transaction');
  return indicators;
}

/**
 * Analyze a JSON response to find list data and field mappings.
 */
function analyzeResponseBody(body: any): ResponseAnalysis | null {
  if (!body || typeof body !== 'object') return null;

  // Try to find the main list in the response
  const candidates: Array<{ path: string; items: any[] }> = [];

  function findArrays(obj: any, currentPath: string, depth: number) {
    if (depth > 4) return;
    if (Array.isArray(obj) && obj.length >= 2) {
      // Check if items are objects (not primitive arrays)
      if (obj.some(item => item && typeof item === 'object' && !Array.isArray(item))) {
        candidates.push({ path: currentPath, items: obj });
      }
    }
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      for (const [key, val] of Object.entries(obj)) {
        const nextPath = currentPath ? `${currentPath}.${key}` : key;
        findArrays(val, nextPath, depth + 1);
      }
    }
  }

  findArrays(body, '', 0);
  if (!candidates.length) return null;

  // Pick the largest array as the main list
  candidates.sort((a, b) => b.items.length - a.items.length);
  const best = candidates[0];

  // Analyze field names in the first item
  const sampleItem = best.items[0];
  const sampleFieldNames = sampleItem && typeof sampleItem === 'object'
    ? flattenFieldNames(sampleItem, '', 2)
    : [];

  // Match fields to semantic roles
  const detectedFields: Record<string, string> = {};
  for (const [role, aliases] of Object.entries(FIELD_ROLES)) {
    for (const fieldName of sampleFieldNames) {
      const basename = fieldName.split('.').pop()?.toLowerCase() ?? '';
      if (aliases.includes(basename)) {
        detectedFields[role] = fieldName;
        break;
      }
    }
  }

  return {
    itemPath: best.path || null,
    itemCount: best.items.length,
    detectedFields,
    sampleFieldNames,
  };
}

/**
 * Flatten nested object field names for analysis.
 */
function flattenFieldNames(obj: any, prefix: string, maxDepth: number): string[] {
  if (maxDepth <= 0 || !obj || typeof obj !== 'object') return [];
  const names: string[] = [];
  for (const key of Object.keys(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    names.push(fullKey);
    if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
      names.push(...flattenFieldNames(obj[key], fullKey, maxDepth - 1));
    }
  }
  return names;
}

/**
 * Analyze a list of network entries into structured endpoints.
 */
function analyzeEndpoints(entries: NetworkEntry[], siteHost: string): AnalyzedEndpoint[] {
  const seen = new Map<string, AnalyzedEndpoint>();

  for (const entry of entries) {
    if (!entry.url) continue;

    // Skip static resources
    const ct = entry.contentType.toLowerCase();
    if (IGNORED_CONTENT_TYPES.has(ct.split(';')[0]?.trim() ?? '') ||
        ct.includes('image/') || ct.includes('font/') || ct.includes('css') ||
        ct.includes('javascript') || ct.includes('wasm')) continue;

    // Skip non-JSON and failed responses
    if (entry.status && entry.status >= 400) continue;

    const pattern = urlToPattern(entry.url);
    const queryParams = extractQueryParams(entry.url);
    const paramNames = Object.keys(queryParams).filter(k => !VOLATILE_PARAMS.has(k));

    const key = `${entry.method}:${pattern}`;
    if (seen.has(key)) continue;

    const endpoint: AnalyzedEndpoint = {
      pattern,
      method: entry.method,
      url: entry.url,
      status: entry.status,
      contentType: ct,
      queryParams: paramNames,
      hasSearchParam: paramNames.some(p => SEARCH_PARAMS.has(p)),
      hasPaginationParam: paramNames.some(p => PAGINATION_PARAMS.has(p)),
      hasLimitParam: paramNames.some(p => LIMIT_PARAMS.has(p)),
      authIndicators: detectAuthIndicators(entry.requestHeaders),
      responseAnalysis: entry.responseBody ? analyzeResponseBody(entry.responseBody) : null,
    };

    seen.set(key, endpoint);
  }

  return [...seen.values()];
}

/**
 * Infer what strategy to use based on endpoint analysis.
 */
function inferStrategy(endpoint: AnalyzedEndpoint): string {
  if (endpoint.authIndicators.includes('signature')) return 'intercept';
  if (endpoint.authIndicators.includes('transaction')) return 'header';
  if (endpoint.authIndicators.includes('bearer') || endpoint.authIndicators.includes('csrf')) return 'header';
  // Check if the URL is a public API (no auth indicators)
  if (endpoint.authIndicators.length === 0) {
    // If it's the same domain, likely cookie auth
    return 'cookie';
  }
  return 'cookie';
}

/**
 * Infer the capability name from an endpoint pattern.
 */
function inferCapabilityName(endpoint: AnalyzedEndpoint, goal?: string): string {
  if (goal) return goal;

  const u = endpoint.url.toLowerCase();
  const p = endpoint.pattern.toLowerCase();

  // Match common patterns
  if (endpoint.hasSearchParam) return 'search';
  if (u.includes('hot') || u.includes('popular') || u.includes('ranking') || u.includes('trending')) return 'hot';
  if (u.includes('feed') || u.includes('timeline') || u.includes('dynamic')) return 'feed';
  if (u.includes('comment') || u.includes('reply')) return 'comments';
  if (u.includes('history')) return 'history';
  if (u.includes('profile') || u.includes('userinfo') || u.includes('/me') || u.includes('myinfo')) return 'me';
  if (u.includes('video') || u.includes('article') || u.includes('detail') || u.includes('view')) return 'detail';
  if (u.includes('favorite') || u.includes('collect') || u.includes('bookmark')) return 'favorite';
  if (u.includes('notification') || u.includes('notice')) return 'notifications';

  // Fallback: try to extract from path
  try {
    const pathname = new URL(endpoint.url).pathname;
    const segments = pathname.split('/').filter(s => s && !s.match(/^\d+$/) && !s.match(/^[0-9a-f]{8,}$/i));
    if (segments.length) return segments[segments.length - 1].replace(/[^a-z0-9]/gi, '_').toLowerCase();
  } catch {}

  return 'data';
}

/**
 * Build recommended columns from response analysis.
 */
function buildRecommendedColumns(analysis: ResponseAnalysis | null): string[] {
  if (!analysis) return ['title', 'url'];
  const cols: string[] = [];
  // Prioritize: title → url → author → score → time
  const priority = ['title', 'url', 'author', 'score', 'time'];
  for (const role of priority) {
    if (analysis.detectedFields[role]) cols.push(role);
  }
  return cols.length ? cols : ['title', 'url'];
}

/**
 * Build recommended args from endpoint query params.
 */
function buildRecommendedArgs(endpoint: AnalyzedEndpoint): InferredCapability['recommendedArgs'] {
  const args: InferredCapability['recommendedArgs'] = [];

  if (endpoint.hasSearchParam) {
    const paramName = endpoint.queryParams.find(p => SEARCH_PARAMS.has(p)) ?? 'keyword';
    args.push({ name: 'keyword', type: 'str', required: true });
  }

  // Always add limit
  args.push({ name: 'limit', type: 'int', required: false, default: 20 });

  if (endpoint.hasPaginationParam) {
    args.push({ name: 'page', type: 'int', required: false, default: 1 });
  }

  return args;
}

/**
 * Score an endpoint's interest level for capability generation.
 * Higher score = more likely to be a useful API endpoint.
 */
function scoreEndpoint(ep: AnalyzedEndpoint): number {
  let score = 0;
  // JSON content type is strongly preferred
  if (ep.contentType.includes('json')) score += 10;
  // Has response analysis with items
  if (ep.responseAnalysis) {
    score += 5;
    score += Math.min(ep.responseAnalysis.itemCount, 10);
    score += Object.keys(ep.responseAnalysis.detectedFields).length * 2;
  }
  // API-like path patterns
  if (ep.pattern.includes('/api/') || ep.pattern.includes('/x/')) score += 3;
  // Has search/pagination params
  if (ep.hasSearchParam) score += 3;
  if (ep.hasPaginationParam) score += 2;
  if (ep.hasLimitParam) score += 2;
  // 200 OK
  if (ep.status === 200) score += 2;
  return score;
}

// ── Framework detection ────────────────────────────────────────────────────

const FRAMEWORK_DETECT_JS = `
(() => {
  const result = {};
  try {
    const app = document.querySelector('#app');
    result.vue3 = !!(app && app.__vue_app__);
    result.vue2 = !!(app && app.__vue__);
    result.react = !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || !!document.querySelector('[data-reactroot]');
    result.nextjs = !!window.__NEXT_DATA__;
    result.nuxt = !!window.__NUXT__;
    if (result.vue3 && app.__vue_app__) {
      const gp = app.__vue_app__.config?.globalProperties;
      result.pinia = !!(gp && gp.$pinia);
      result.vuex = !!(gp && gp.$store);
    }
  } catch {}
  return JSON.stringify(result);
})()
`;

// ── Main explore function ──────────────────────────────────────────────────

export async function exploreUrl(url: string, opts: any = {}): Promise<any> {
  const site = opts.site ?? detectSiteName(url);
  const outDir = opts.outDir ?? path.join('.opencli', 'explore', site);
  fs.mkdirSync(outDir, { recursive: true });

  const result: any = await browserSession(opts.BrowserFactory, async (page: any) => {
    return runWithTimeout((async () => {
      // Step 1: Navigate
      await page.goto(url);
      await page.wait(opts.waitSeconds ?? 3);

      // Step 2: Auto-scroll to trigger lazy loading
      for (let i = 0; i < 3; i++) {
        await page.scroll('down');
        await page.wait(1);
      }

      // Step 3: Capture network traffic
      const rawNetwork = await page.networkRequests(false);
      const networkEntries = parseNetworkOutput(rawNetwork);

      // Step 4: For JSON endpoints, try to fetch response body in-browser
      const jsonEndpoints = networkEntries.filter(e =>
        e.contentType.includes('json') && e.method === 'GET' && e.status === 200
      );

      for (const ep of jsonEndpoints.slice(0, 10)) {
        // Only fetch body for promising-looking API endpoints
        if (ep.url.includes('/api/') || ep.url.includes('/x/') || ep.url.includes('/web/') ||
            ep.contentType.includes('json')) {
          try {
            const bodyResult = await page.evaluate(`
              async () => {
                try {
                  const resp = await fetch(${JSON.stringify(ep.url)}, { credentials: 'include' });
                  if (!resp.ok) return null;
                  const data = await resp.json();
                  return JSON.stringify(data).slice(0, 10000);
                } catch { return null; }
              }
            `);
            if (bodyResult && typeof bodyResult === 'string') {
              try { ep.responseBody = JSON.parse(bodyResult); } catch {}
            } else if (bodyResult && typeof bodyResult === 'object') {
              ep.responseBody = bodyResult;
            }
          } catch {}
        }
      }

      // Step 5: Detect frontend framework
      let framework: Record<string, boolean> = {};
      try {
        const fwResult = await page.evaluate(FRAMEWORK_DETECT_JS);
        if (typeof fwResult === 'string') framework = JSON.parse(fwResult);
        else if (typeof fwResult === 'object') framework = fwResult;
      } catch {}

      // Step 6: Get page metadata
      let title = '', finalUrl = '';
      try {
        const meta = await page.evaluate(`
          () => JSON.stringify({ url: window.location.href, title: document.title || '' })
        `);
        if (typeof meta === 'string') {
          const parsed = JSON.parse(meta);
          title = parsed.title; finalUrl = parsed.url;
        } else if (typeof meta === 'object') {
          title = meta.title; finalUrl = meta.url;
        }
      } catch {}

      // Step 7: Analyze endpoints
      let siteHost = '';
      try { siteHost = new URL(url).hostname; } catch {}
      const analyzedEndpoints = analyzeEndpoints(networkEntries, siteHost);

      // Step 8: Score and rank endpoints
      const scoredEndpoints = analyzedEndpoints
        .map(ep => ({ ...ep, score: scoreEndpoint(ep) }))
        .filter(ep => ep.score >= 5)
        .sort((a, b) => b.score - a.score);

      // Step 9: Infer capabilities from top endpoints
      const capabilities: InferredCapability[] = [];
      const usedNames = new Set<string>();

      for (const ep of scoredEndpoints.slice(0, 8)) {
        let capName = inferCapabilityName(ep, opts.goal);
        // Deduplicate names
        if (usedNames.has(capName)) {
          const suffix = ep.pattern.split('/').filter(s => s && !s.startsWith('{') && !s.includes('.')).pop();
          capName = suffix ? `${capName}_${suffix}` : `${capName}_${usedNames.size}`;
        }
        usedNames.add(capName);

        capabilities.push({
          name: capName,
          description: `${site} ${capName}`,
          strategy: inferStrategy(ep),
          confidence: Math.min(ep.score / 20, 1.0),
          endpoint: ep.pattern,
          itemPath: ep.responseAnalysis?.itemPath ?? null,
          recommendedColumns: buildRecommendedColumns(ep.responseAnalysis),
          recommendedArgs: buildRecommendedArgs(ep),
        });
      }

      // Step 10: Determine auth strategy
      const allAuthIndicators = new Set(analyzedEndpoints.flatMap(ep => ep.authIndicators));
      let topStrategy = 'cookie';
      if (allAuthIndicators.has('signature')) topStrategy = 'intercept';
      else if (allAuthIndicators.has('transaction') || allAuthIndicators.has('bearer')) topStrategy = 'header';
      else if (allAuthIndicators.size === 0 && scoredEndpoints.some(ep => ep.contentType.includes('json'))) topStrategy = 'public';

      return {
        site,
        target_url: url,
        final_url: finalUrl,
        title,
        framework,
        top_strategy: topStrategy,
        endpoint_count: analyzedEndpoints.length,
        api_endpoint_count: scoredEndpoints.length,
        capabilities,
        endpoints: scoredEndpoints.map(ep => ({
          pattern: ep.pattern,
          method: ep.method,
          url: ep.url,
          status: ep.status,
          contentType: ep.contentType,
          score: ep.score,
          queryParams: ep.queryParams,
          itemPath: ep.responseAnalysis?.itemPath ?? null,
          itemCount: ep.responseAnalysis?.itemCount ?? 0,
          detectedFields: ep.responseAnalysis?.detectedFields ?? {},
          authIndicators: ep.authIndicators,
        })),
        auth_indicators: [...allAuthIndicators],
      };
    })(), { timeout: DEFAULT_BROWSER_EXPLORE_TIMEOUT, label: 'explore' });
  });

  // Write artifacts
  const manifest = {
    site: result.site,
    target_url: result.target_url,
    final_url: result.final_url,
    title: result.title,
    framework: result.framework,
    top_strategy: result.top_strategy,
    explored_at: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  fs.writeFileSync(path.join(outDir, 'endpoints.json'), JSON.stringify(result.endpoints ?? [], null, 2));
  fs.writeFileSync(path.join(outDir, 'capabilities.json'), JSON.stringify(result.capabilities ?? [], null, 2));
  fs.writeFileSync(path.join(outDir, 'auth.json'), JSON.stringify({
    top_strategy: result.top_strategy,
    indicators: result.auth_indicators ?? [],
    framework: result.framework ?? {},
  }, null, 2));

  return { ...result, out_dir: outDir };
}

export function renderExploreSummary(result: any): string {
  const lines = [
    'opencli explore: OK',
    `Site: ${result.site}`,
    `URL: ${result.target_url}`,
    `Title: ${result.title || '(none)'}`,
    `Strategy: ${result.top_strategy}`,
    `Endpoints: ${result.endpoint_count} total, ${result.api_endpoint_count} API`,
    `Capabilities: ${result.capabilities?.length ?? 0}`,
  ];
  for (const cap of (result.capabilities ?? []).slice(0, 5)) {
    lines.push(`  • ${cap.name} (${cap.strategy}, confidence: ${(cap.confidence * 100).toFixed(0)}%)`);
  }
  const fw = result.framework ?? {};
  const fwNames = Object.entries(fw).filter(([, v]) => v).map(([k]) => k);
  if (fwNames.length) lines.push(`Framework: ${fwNames.join(', ')}`);
  lines.push(`Output: ${result.out_dir}`);
  return lines.join('\n');
}
