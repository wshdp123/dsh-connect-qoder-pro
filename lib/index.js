// dsh-connect-qoder-pro — zero-config Qoder CN connect for DeepSeek Harness.
// Reuses the Qoder desktop app's (CN edition) local sign-in; read-only.
//
// Pipeline: DSH PiAiAdapter -> loopback shim (OpenAI-compatible) -> Qoder CN
// gateway (COSY signature + permuted body encoding + doubly-wrapped SSE).
//
// Protocol facts verified end to end on 2026-10-16 (see D:\DSH\_qoder-probe):
// model/list 200 with 14 chat models; real chat 200 with OpenAI chunks.

import { timingSafeEqual, randomBytes, createDecipheriv } from "node:crypto";
import { readFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { NO_COST, QoderCatalog, chatStream, fetchCampaigns, fetchModelCatalog, fetchUsage, claimCampaign, claimableCampaignOf, checkinStateFrom, normalizeClaimResult, campaignIsClaimed, normalizeCatalogRow, prepareChatBody, toEpochMs } from "./protocol.js";
import { Readable } from "node:stream";
import z from "@deepseek-ai/schemastery";
import { resolveRetryPolicy } from "@deepseek-ai/dsh-llm";
import { createProvider } from "@earendil-works/pi-ai";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { PiAiAdapter } from "@deepseek-ai/dsh-llm-pi-ai";

const CN_REGION = {
	id: "cn",
	displayName: "Qoder",
	providerId: "qoder-cn",
	baseUrl: "https://gateway.qoder.com.cn/",
	openApiUrl: "https://openapi.qoder.com.cn",
	authDirName: "com.qodercn.app.stable",
	manageUrl: "https://qoder.com.cn",
	downloadUrl: "https://qoder.com.cn/download",
};
const ROUTE_PREFIX = "/plugins/dsh-connect-qoder-pro";

//#region credentials (OSCrypt + DPAPI, host-side)
const DPAPI_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class QpDsh {
  [StructLayout(LayoutKind.Sequential)] public struct B { public int cbData; public IntPtr pbData; }
  [DllImport("Crypt32.dll", SetLastError=true)] static extern bool CryptUnprotectData(ref B i, IntPtr d, IntPtr e, IntPtr r, IntPtr p, int f, ref B o);
  [DllImport("Kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  public static byte[] U(byte[] data) {
    B i = new B(); i.cbData = data.Length; i.pbData = Marshal.AllocHGlobal(data.Length);
    Marshal.Copy(data, 0, i.pbData, data.Length); B o = new B();
    try {
      if (!CryptUnprotectData(ref i, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref o)) throw new Exception("DPAPI error");
      byte[] r = new byte[o.cbData]; Marshal.Copy(o.pbData, r, 0, o.cbData); return r;
    } finally { Marshal.FreeHGlobal(i.pbData); if (o.pbData != IntPtr.Zero) LocalFree(o.pbData); }
  }
}
'@
$statePath = Join-Path $env:QP_APP_DIR 'Local State'
$json = Get-Content $statePath -Raw | ConvertFrom-Json
$raw = [Convert]::FromBase64String($json.os_crypt.encrypted_key)
$key = [QpDsh]::U($raw[5..($raw.Length - 1)])
[IO.File]::WriteAllText($env:QP_KEY_OUT, [Convert]::ToBase64String($key))
`;
/** Unwrap the app's OSCrypt master key via PowerShell DPAPI (temp-file handoff). */
function unwrapOscryptKey(appDir) {
	const dir = join(tmpdir(), `qoder-pro-dsh-${process.pid}-${Date.now()}`);
	const out = join(dir, "key.b64");
	try {
		mkdirSync(dir, { recursive: true });
		const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", DPAPI_SCRIPT], {
			env: { ...process.env, QP_APP_DIR: appDir, QP_KEY_OUT: out },
			encoding: "utf8",
			timeout: 30000,
			windowsHide: true,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (r.status !== 0 || !existsSync(out)) {
			throw new Error(`dpapi unwrap failed (exit ${r.status}): ${String(r.stderr ?? "").slice(0, 300)}`);
		}
		const key = Buffer.from(readFileSync(out, "utf8").trim(), "base64");
		if (key.length !== 32) throw new Error(`oscrypt key length ${key.length}, expected 32`);
		return key;
	} finally {
		try { rmSync(dir, { recursive: true, force: true }); } catch {}
	}
}
/** Decrypt the v10 AES-256-GCM OSCrypt envelope. */
function decryptOscrypt(blob, key) {
	if (blob.length < 31) throw new Error("auth blob too short");
	if (blob.subarray(0, 3).toString("latin1") !== "v10") throw new Error("auth blob has a bad OSCrypt prefix");
	const body = blob.subarray(3);
	const nonce = body.subarray(0, 12);
	const tag = body.subarray(body.length - 16);
	const ct = body.subarray(12, body.length - 16);
	const d = createDecipheriv("aes-256-gcm", key, nonce);
	d.setAuthTag(tag);
	return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
/**
 * Read the desktop credential, or undefined when signed out / unreadable.
 * Failures are reported on the returned object so the sweep can log them.
 */
function readDesktopCredential(region) {
	// Test/CI escape hatch: a pre-unwrapped session JSON can be supplied via env
	// (same shape as auth.v1.dat plaintext). Production hosts never set it.
	const injected = process.env.DSH_QODER_PRO_SESSION;
	if (injected) {
		try {
			const session = JSON.parse(Buffer.from(injected, "base64").toString("utf8"));
			if (typeof session.token === "string" && session.token !== "" && typeof session.user?.id === "string") {
				return { credential: { userID: session.user.id, token: session.token, name: session.user?.name ?? "", email: session.user?.email ?? "", machineID: "", identity: `${session.user.id}`, expiresAt: session.expiresAt } };
			}
		} catch {}
	}
	const appDir = join(process.env.APPDATA ?? "", region.authDirName);
	const authDat = join(appDir, "auth.v1.dat");
	if (!existsSync(authDat)) return { credential: void 0, error: "Qoder desktop sign-in not found (auth.v1.dat missing)" };
	try {
		const key = unwrapOscryptKey(appDir);
		const session = JSON.parse(decryptOscrypt(readFileSync(authDat), key));
		const token = session.token;
		const uid = session.user?.id;
		if (typeof token !== "string" || token === "" || typeof uid !== "string" || uid === "") {
			return { credential: void 0, error: "Qoder desktop auth file has no usable session" };
		}
		if (typeof session.expiresAt === "string" && new Date(session.expiresAt) <= new Date()) {
			return { credential: void 0, error: "Qoder desktop session expired (open the app to refresh)" };
		}
		return {
			credential: {
				userID: uid,
				token,
				name: session.user?.name ?? "",
				email: session.user?.email ?? "",
				machineID: "",
				identity: `${uid}`,
				expiresAt: session.expiresAt,
			},
		};
	} catch (error) {
		return { credential: void 0, error: error instanceof Error ? error.message.slice(0, 300) : String(error) };
	}
}
//#endregion

//#region loopback shim
const REQUEST_BODY_LIMIT = 67108864;
const KIND_STATUS = {
	hard_credit: 402,
	soft_rate: 429,
	session_dead: 401,
	not_found: 502,
	server: 502,
	client: 400,
};
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
function hostnameOfHost(host) {
	let hostname = host.trim().toLowerCase();
	if (hostname.startsWith("[")) {
		const end = hostname.indexOf("]");
		return end === -1 ? hostname : hostname.slice(0, end + 1);
	}
	const colon = hostname.lastIndexOf(":");
	if (colon !== -1 && !hostname.slice(0, colon).includes(":") && /^\d+$/.test(hostname.slice(colon + 1))) hostname = hostname.slice(0, colon);
	return hostname;
}
function hostIsLoopback(host) {
	if (host === void 0 || host.trim() === "") return false;
	return LOOPBACK_HOSTS.has(hostnameOfHost(host));
}
function originIsLoopback(origin) {
	if (origin === void 0 || origin.trim() === "") return true;
	try {
		const { hostname } = new URL(origin);
		return LOOPBACK_HOSTS.has(hostname) || hostname === "::1";
	} catch {
		return false;
	}
}
function writeJson(res, status, body) {
	const payload = JSON.stringify(body);
	res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
	res.end(payload);
}
function writeOpenAIError(res, status, kind, message) {
	writeJson(res, status, { error: { message, type: kind, code: kind } });
}
function readRequestBody(req, limit = REQUEST_BODY_LIMIT) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let size = 0;
		req.on("data", (chunk) => {
			size += chunk.length;
			if (size > limit) {
				reject(new Error("request body too large"));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}
/**
 * Same-origin gate shared by the OpenAI endpoint and the plugin routes:
 * the browser surface is same-origin with the DSH web server, which proxies
 * these paths onto the loopback shim with the bearer secret attached.
 */
function sameOriginRequest(req) {
	const origin = req.headers.origin;
	if (typeof origin === "string" && origin.trim() !== "") {
		if (!originIsLoopback(origin)) return false;
		const host = req.headers.host;
		if (typeof host === "string" && host.trim() !== "") {
			let authority;
			try {
				authority = new URL(origin).host.toLowerCase();
			} catch {
				return false;
			}
			if (authority !== host.trim().toLowerCase()) return false;
		}
	}
	return true;
}
function methodAllowed(req, res, ...methods) {
	const method = req.method ?? "";
	if (methods.includes(method)) return true;
	if (method === "HEAD" && methods.includes("GET")) return true;
	const advertised = methods.includes("GET") ? [...methods, "HEAD"] : methods;
	writeJson(res, 405, { error: "method not allowed", allow: advertised });
	res.setHeader("Allow", advertised.join(","));
	return false;
}
/**
 * The loopback OpenAI-compatible endpoint. pi-ai points here; the shim
 * translates to the Qoder wire protocol and streams back OpenAI SSE.
 */
function createQoderShim(options) {
	const { region, catalog, logger } = options;
	const SHARED_SECRET = randomBytes(32).toString("base64url");
	function bearerOk(req) {
		const header = req.headers.authorization;
		if (typeof header !== "string") return false;
		const match = /^Bearer\s+(.+)$/i.exec(header.trim());
		if (match === null) return false;
		const a = Buffer.from(match[1]);
		const b = Buffer.from(SHARED_SECRET);
		return a.length === b.length && timingSafeEqual(a, b);
	}
	const server = createServer((req, res) => {
		handle(req, res).catch((error) => {
			if (!res.headersSent) writeOpenAIError(res, 500, "internal", String(error));
			else res.end();
		});
	});
	const ready = new Promise((resolve, reject) => {
		server.once("listening", () => resolve());
		server.once("error", reject);
	});
	server.listen(0, "127.0.0.1");
	const baseUrl = () => {
		const address = server.address();
		if (address === null || typeof address === "string") throw new Error("qoder shim has no listening address");
		return `http://127.0.0.1:${address.port}`;
	};
	async function handle(req, res) {
		if (!hostIsLoopback(req.headers.host)) {
			writeOpenAIError(res, 403, "host_not_allowed", "Host header must name the loopback interface");
			return;
		}
		if (!originIsLoopback(req.headers.origin)) {
			writeOpenAIError(res, 403, "origin_not_allowed", "Origin must be a loopback origin");
			return;
		}
		const url = (req.url ?? "/").split("?")[0];
		// Plugin routes (check-in / usage / account): proxied same-origin from
		// the DSH web server, so they use the same-origin gate, not the bearer.
		if (url === `${ROUTE_PREFIX}/status` || url === `${ROUTE_PREFIX}/status/`) {
			await statusRoute(req, res);
			return;
		}
		if (url === `${ROUTE_PREFIX}/usage` || url === `${ROUTE_PREFIX}/usage/`) {
			await usageRoute(req, res);
			return;
		}
		if (url === `${ROUTE_PREFIX}/checkin` || url === `${ROUTE_PREFIX}/checkin/`) {
			await checkinRoute(req, res);
			return;
		}
		if (url === `${ROUTE_PREFIX}/account` || url === `${ROUTE_PREFIX}/account/`) {
			await accountRoute(req, res);
			return;
		}
		if (!bearerOk(req)) {
			writeOpenAIError(res, 401, "unauthorized", "missing or invalid Authorization bearer");
			return;
		}
		if (req.method === "GET" && (url === "/healthz" || url === "/healthz/")) {
			writeJson(res, 200, { ok: true });
			return;
		}
		if (req.method === "GET" && (url === "/v1/models" || url === "/v1/models/")) {
			writeJson(res, 200, {
				object: "list",
				data: catalog.current().map((model) => ({ id: model.id, object: "model", created: 0, owned_by: "qoder" })),
			});
			return;
		}
		if (req.method === "POST" && (url === "/v1/chat/completions" || url === "/v1/chat/completions/")) {
			await chatCompletions(req, res);
			return;
		}
		writeOpenAIError(res, 404, "not_found", `no such route: ${req.method} ${url}`);
	}
	//#region plugin routes (check-in / usage / account)
	const USAGE_TTL_MS = 20000;
	const usageCache = { value: void 0, at: 0, flight: void 0 };
	/** 20s TTL + single-flight; invalidateUsage() drops the cache after a claim. */
	async function readUsage(credential, force) {
		const now = Date.now();
		if (!force && usageCache.value !== void 0 && now - usageCache.at < USAGE_TTL_MS) return usageCache.value;
		if (usageCache.flight !== void 0) return await usageCache.flight;
		const flight = (async () => {
			try {
				const usage = await fetchUsage(credential, region);
				usageCache.value = usage;
				usageCache.at = Date.now();
				return usage;
			} finally {
				usageCache.flight = void 0;
			}
		})();
		usageCache.flight = flight;
		return await flight;
	}
	function invalidateUsage() {
		usageCache.value = void 0;
		usageCache.at = 0;
		usageCache.flight = void 0;
	}
	function regionState() {
		const credential = options.resolveCredential();
		return {
			region: region.id,
			regionName: region.displayName,
			manageUrl: region.manageUrl,
			downloadUrl: region.downloadUrl,
			signedIn: credential !== void 0,
			started: catalog.isVisible(),
			models: catalog.current().length,
			error: options.credentialError(),
		};
	}
	async function statusRoute(req, res) {
		if (!sameOriginRequest(req)) {
			writeJson(res, 403, { error: "origin-not-trusted" });
			return;
		}
		if (!methodAllowed(req, res, "GET")) return;
		// Error NAME only — a message could leak credential paths to the browser.
		const registrationError = options.registrationError?.();
		writeJson(res, 200, {
			activated: true,
			startedRegions: [regionState()],
			providerRegistration: registrationError === void 0 ? { ok: true } : { ok: false, errorName: String(registrationError) },
		});
	}
	async function usageRoute(req, res) {
		if (!sameOriginRequest(req)) {
			writeJson(res, 403, { error: "origin-not-trusted" });
			return;
		}
		if (!methodAllowed(req, res, "GET")) return;
		const credential = options.resolveCredential();
		if (credential === void 0) {
			writeJson(res, 200, { available: false, reason: options.credentialError() ?? "not-signed-in", regions: [regionState()] });
			return;
		}
		const force = new URL(`http://127.0.0.1${req.url ?? "/"}`).searchParams.get("refresh") === "1";
		try {
			const usage = await readUsage(credential, force);
			let checkin;
			try {
				checkin = checkinStateFrom(await fetchCampaigns(credential, region));
			} catch (error) {
				options.logger?.warn?.("dsh-connect-qoder-pro: campaigns unavailable", error instanceof Error ? error.message : String(error));
			}
			writeJson(res, 200, { available: usage !== void 0, regions: [{ ...regionState(), usage, checkin }] });
		} catch (error) {
			writeJson(res, 200, { available: false, reason: error instanceof Error ? error.message.slice(0, 300) : String(error), regions: [regionState()] });
		}
	}
	async function checkinRoute(req, res) {
		if (!sameOriginRequest(req)) {
			writeJson(res, 403, { error: "origin-not-trusted" });
			return;
		}
		if (!methodAllowed(req, res, "POST")) return;
		const credential = options.resolveCredential();
		if (credential === void 0) {
			writeJson(res, 502, { error: options.credentialError() ?? "not-signed-in" });
			return;
		}
		try {
			const payload = await fetchCampaigns(credential, region);
			const campaign = claimableCampaignOf(payload);
			if (campaign === void 0) throw new Error("Qoder is not running a check-in for this account today");
			if (campaignIsClaimed(campaign)) {
				writeJson(res, 200, { claimed: false, replayed: true, alreadyClaimed: true, checkin: checkinStateFrom(payload) });
				return;
			}
			if (typeof campaign.campaignId !== "string") throw new Error("campaign has no id");
			const result = normalizeClaimResult(await claimCampaign(credential, region, campaign.campaignId), campaign);
			if (!result.claimed) throw new Error("Qoder did not confirm this check-in");
			invalidateUsage();
			options.logger?.info?.("dsh-connect-qoder-pro: daily check-in claimed", String(result.amount ?? ""));
			const checkin = checkinStateFrom(await fetchCampaigns(credential, region).catch(() => payload));
			writeJson(res, 200, { ...result, checkin });
		} catch (error) {
			writeJson(res, 502, { error: error instanceof Error ? error.message.slice(0, 300) : String(error) });
		}
	}
	async function accountRoute(req, res) {
		if (!sameOriginRequest(req)) {
			writeJson(res, 403, { error: "origin-not-trusted" });
			return;
		}
		if (!methodAllowed(req, res, "GET")) return;
		const credential = options.resolveCredential();
		if (credential === void 0) {
			writeJson(res, 200, { signedIn: false, error: options.credentialError() ?? "not-signed-in" });
			return;
		}
		writeJson(res, 200, {
			signedIn: true,
			user: { id: credential.userID, name: credential.name ?? "", email: credential.email ?? "" },
			expiresAt: credential.expiresAt !== void 0 ? toEpochMs(credential.expiresAt) : void 0,
		});
	}
	//#endregion
	async function chatCompletions(req, res) {
		const contentType = req.headers["content-type"];
		if (typeof contentType !== "string" || !contentType.trim().toLowerCase().startsWith("application/json")) {
			writeOpenAIError(res, 415, "unsupported_media_type", "Content-Type must be application/json");
			return;
		}
		const credential = options.resolveCredential();
		if (credential === void 0) {
			writeOpenAIError(res, 401, "not_signed_in", options.credentialError() ?? "Qoder desktop sign-in not available");
			return;
		}
		let prepared;
		try {
			prepared = prepareChatBody((await readRequestBody(req)).toString("utf8"));
		} catch (error) {
			writeOpenAIError(res, 400, "client", error instanceof Error ? error.message : String(error));
			return;
		}
		const controller = new AbortController();
		req.on("close", () => controller.abort());
		let iterator;
		try {
			iterator = chatStream(credential, prepared, region, controller.signal);
		} catch (error) {
			writeOpenAIError(res, KIND_STATUS[error.kind] ?? 502, error.kind ?? "server", error.message ?? String(error));
			return;
		}
		res.writeHead(200, {
			"Content-Type": "text/event-stream",
			"Cache-Control": "no-cache",
			"Connection": "keep-alive",
			"X-Accel-Buffering": "no",
		});
		let sawDone = false;
		try {
			for await (const { chunk } of iterator) {
				if (chunk?.choices?.[0]?.finish_reason === "stop" || chunk?.choices?.[0]?.finish_reason === "length") sawDone = true;
				res.write(`data: ${JSON.stringify(chunk)}\n\n`);
			}
		} catch (error) {
			const kind = error?.kind ?? "server";
			const message = error?.message ?? String(error);
			logger?.warn?.(`dsh-connect-qoder-pro: upstream stream failed (${kind})`, message);
			if (!sawDone) {
				const payload = JSON.stringify({ error: { message: `qoder upstream ${kind}: ${message}`, type: kind, code: kind } });
				res.write(`data: ${payload}\n\n`);
			}
		} finally {
			if (!sawDone) res.write("data: [DONE]\n\n");
			res.end();
		}
	}
	return {
		ready,
		baseUrl,
		token: () => SHARED_SECRET,
		close: () => new Promise((resolve) => {
			server.close(() => resolve());
			server.closeAllConnections?.();
		}),
	};
}
//#endregion

//#region adapter
	// pi-ai auto-detects a loopback baseUrl as developer-role capable; Qoder
	// rejects role:"developer" with 403/10605, so it must be disabled explicitly.
	// maxTokens pinned at 65536 (PROBED): the unset default of 32768 halves the
	// budget reasoning models share between thinking and the answer.
	const PROBED_MAX_TOKENS = 65536;
	/** Build one pi-ai model descriptor pointing at the loopback shim. */
	function toPiModel(info, baseUrl, providerId) {
		const reasoningFields = info.reasoning
			? {
				reasoning: true,
				thinkingLevelMap: { off: null, minimal: null, low: null, medium: null, high: null, xhigh: null, max: null },
			}
			: { reasoning: false };
		return {
			id: info.id,
			name: info.name,
			api: "openai-completions",
			provider: providerId,
			baseUrl,
			input: info.supportsImages ? ["text", "image"] : ["text"],
			...reasoningFields,
			cost: NO_COST,
			contextWindow: info.contextWindow,
			maxTokens: PROBED_MAX_TOKENS,
			compat: { maxTokensField: "max_tokens", supportsDeveloperRole: false },
		};
	}
function createQoderAdapter(options) {
	const { shim, catalog, providerId, displayName } = options;
	const buildModels = () => {
		const baseUrl = `${shim.baseUrl()}/v1`;
		return catalog.current().map((info) => toPiModel(info, baseUrl, providerId));
	};
	const provider = {
		...createProvider({
			id: providerId,
			name: displayName,
			auth: { apiKey: {
				name: "Qoder desktop session",
				async resolve() {
					return { auth: { apiKey: shim.token() }, source: "Qoder" };
				},
			} },
			models: buildModels(),
			api: openAICompletionsApi(),
		}),
		getModels: () => buildModels(),
	};
	const profile = {
		provider: providerId,
		displayName,
		streamIdleTimeoutMs: 300000,
		retryPolicy: resolveRetryPolicy(void 0, "dsh-connect-qoder-pro retryPolicy"),
		configuredMaxTokens: new Map(),
		modelErrors: new Map(),
		maxRequestImageBytes: 20971520,
		requestImagePixelBudget: 4194304,
		piProvider: provider,
	};
	const profiles = new Map([[providerId, profile]]);
	return new QoderPiAiAdapter(catalog, {
		profiles: () => profiles,
		auth: {
			credentials: {
				read: async () => void 0,
				list: async () => [],
				modify: async () => {},
				delete: async () => {},
			},
			authContext: { env: {}, fileExists: async () => false },
		},
		resolveApiKey: async () => shim.token(),
	});
}
/** The Qoder adapter: PiAiAdapter with catalog display names layered on. */
var QoderPiAiAdapter = class extends PiAiAdapter {
	catalog;
	constructor(catalog, options) {
		super(options);
		this.catalog = catalog;
		this.profiles = options.profiles;
	}
	infoFor(model) {
		return this.catalog.current().find((entry) => entry.id === model);
	}
	async listModels(provider) {
		const models = await super.listModels(provider);
		return models.flatMap((model) => {
			const info = this.infoFor(model.id);
			if (info === void 0) return [model];
			return [{ ...model, name: info.name }];
		});
	}
	async resolveModel(provider, model, signal) {
		const resolved = await super.resolveModel(provider, model, signal);
		const info = this.infoFor(model);
		if (info === void 0) return resolved;
		return { ...resolved, name: info.name };
	}
};
//#endregion

//#region plugin surface
const name = "llm-qoder-pro";
const inject = ["llm"];
const Config = z.object({});
const CREDENTIAL_POLL_MS = 30000;

function apply(ctx, config) {
	const catalog = new QoderCatalog();
	let credentialState = { credential: void 0, error: void 0 };
	let registrationError;
	const resolveCredential = () => credentialState.credential;
	const credentialError = () => credentialState.error;
	const refreshCredential = () => {
		const next = readDesktopCredential(CN_REGION);
		const changedIdentity = (next.credential?.identity ?? void 0) !== (credentialState.credential?.identity ?? void 0);
		credentialState = next;
		if (next.error !== void 0) ctx.logger?.warn?.(`dsh-connect-qoder-pro: ${next.error}`);
		return changedIdentity;
	};
	const started = (async () => {
		const shim = createQoderShim({ region: CN_REGION, catalog, logger: ctx.logger, resolveCredential, credentialError, registrationError: () => registrationError });
		try {
			await shim.ready;
		} catch (error) {
			ctx.logger?.error?.("dsh-connect-qoder-pro: loopback endpoint failed to start", error);
			return;
		}
		try {
			const adapter = createQoderAdapter({
				providerId: CN_REGION.providerId,
				displayName: CN_REGION.displayName,
				shim,
				catalog,
			});
			const releaseAdapter = ctx.llm.registerAdapter([CN_REGION.providerId], adapter) ?? (() => {});
			let released = false;
			const dispose = () => {
				if (released) return;
				released = true;
				releaseAdapter();
				shim.close();
			};
			ctx.effect(() => dispose());
			// Initial credential + catalog, then a light poll keeps a sign-in
			// that happens while DSH is running from needing a restart.
			let lastIdentity;
			const fetchCatalog = async () => {
				const credential = credentialState.credential;
				if (credential === void 0) {
					if (catalog.isVisible()) {
						catalog.set([]);
						catalog.setVisible(false);
						ctx.emit?.("llm/adapters-updated");
					}
					return;
				}
				try {
					const rows = await fetchModelCatalog(credential, CN_REGION);
					catalog.set(rows.map(normalizeCatalogRow));
					catalog.setVisible(true);
					ctx.logger?.info?.(`dsh-connect-qoder-pro: ${rows.length} Qoder models available`);
					ctx.emit?.("llm/adapters-updated");
				} catch (error) {
					ctx.logger?.warn?.(`dsh-connect-qoder-pro: catalog unavailable; keeping previous list`, error instanceof Error ? error.message : String(error));
				}
			};
			const sweep = async () => {
				const changed = refreshCredential();
				if (changed || !catalog.isVisible()) await fetchCatalog();
			};
			refreshCredential();
			await fetchCatalog();
			const timer = setInterval(() => {
				sweep().catch((error) => ctx.logger?.warn?.("dsh-connect-qoder-pro: sweep failed", error));
			}, CREDENTIAL_POLL_MS);
			timer.unref?.();
		} catch (error) {
			registrationError = error;
			ctx.logger?.error?.("dsh-connect-qoder-pro: provider registration failed", error);
			shim.close();
		}
	})();
	// Never leave an unhandled rejection if startup throws before await points.
	started.catch(() => {});
}
//#endregion

export { name, inject, apply, Config };
