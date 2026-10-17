// dsh-connect-qoder-pro — Qoder wire protocol (zero host dependencies).
// Extracted verbatim from lib/index.js so it can be tested standalone.
import { createHash, createCipheriv, randomUUID, publicEncrypt, constants } from "node:crypto";


// --- COSY signing primitives (moved from index.js head) ---
const QODER_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`;
const COSY_VERSION = "1.1.38";
const CLIENT_TYPE = "5";
const MACHINE_TYPE = "5";
const DATA_POLICY = "disagree";
const LOGIN_VERSION = "v2";
const MACHINE_OS = "x86_64_windows";

const CUSTOM_ALPHABET = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!";
const STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ENCODE_TABLE = (() => {
	const t = new Uint8Array(256);
	for (let i = 0; i < 256; i++) t[i] = i;
	for (let i = 0; i < 64; i++) t[STD_ALPHABET.charCodeAt(i)] = CUSTOM_ALPHABET.charCodeAt(i);
	t["=".charCodeAt(0)] = "$".charCodeAt(0);
	return t;
})();
/** Encode=1 body encoding: base64 -> permuted alphabet -> one-third rotation. */
function encodeBody(plaintext) {
	const std = Buffer.from(plaintext).toString("base64");
	const n = std.length, third = Math.floor(n / 3);
	const out = Buffer.allocUnsafe(n);
	let dst = 0;
	for (let i = n - third; i < n; i++) out[dst++] = ENCODE_TABLE[std.charCodeAt(i)] ?? std.charCodeAt(i);
	for (let i = third; i < n - third; i++) out[dst++] = ENCODE_TABLE[std.charCodeAt(i)] ?? std.charCodeAt(i);
	for (let i = 0; i < third; i++) out[dst++] = ENCODE_TABLE[std.charCodeAt(i)] ?? std.charCodeAt(i);
	return out;
}
function aesEncryptCBCBase64(plaintext, keyString) {
	const key = Buffer.from(keyString);
	const c = createCipheriv("aes-128-cbc", key, key);
	return c.update(plaintext, "utf8", "base64") + c.final("base64");
}
function signaturePath(url) {
	let p = new URL(url).pathname;
	if (p.startsWith("/algo")) p = p.slice(5);
	return p;
}
function authHeaders(bodyBytes, url, credential) {
	const aesKey = randomUUID().replace(/-/g, "").slice(0, 16);
	const infoB64 = aesEncryptCBCBase64(JSON.stringify({
		uid: credential.userID,
		security_oauth_token: credential.token,
		name: credential.name ?? "",
		aid: "",
		email: credential.email ?? "",
	}), aesKey);
	const cosyKey = publicEncrypt({ key: QODER_RSA_PUBLIC_KEY, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(aesKey)).toString("base64");
	const timestamp = Math.floor(Date.now() / 1e3).toString();
	const payloadB64 = Buffer.from(JSON.stringify({
		version: "v1",
		requestId: randomUUID(),
		info: infoB64,
		cosyVersion: COSY_VERSION,
		ideVersion: "",
	})).toString("base64");
	const path = signaturePath(url);
	const sig = createHash("md5").update(payloadB64).update("\n").update(cosyKey).update("\n").update(timestamp)
		.update("\n").update(bodyBytes).update("\n").update(path).digest("hex");
	const machineID = credential.machineID ?? "";
	return {
		Authorization: `Bearer COSY.${payloadB64}.${sig}`,
		"Cosy-Key": cosyKey,
		"Cosy-User": credential.userID,
		"Cosy-Date": timestamp,
		"Cosy-Version": COSY_VERSION,
		"Cosy-Machineid": machineID,
		"Cosy-Machinetoken": machineID,
		"Cosy-Machinetype": MACHINE_TYPE,
		"Cosy-Machineos": MACHINE_OS,
		"Cosy-Clienttype": CLIENT_TYPE,
		"Cosy-Clientip": "127.0.0.1",
		"Cosy-Bodyhash": createHash("md5").update(bodyBytes).digest("hex"),
		"Cosy-Bodylength": String(bodyBytes.length),
		"Cosy-Sigpath": path,
		"Cosy-Data-Policy": DATA_POLICY,
		"Cosy-Organization-Id": "",
		"Cosy-Organization-Tags": "",
		"Login-Version": LOGIN_VERSION,
		"X-Request-Id": randomUUID(),
	};
}
const CHAT_PATH = "algo/api/v2/service/pro/sse/agent_chat_generation";
const MODELS_PATH = "algo/api/v2/model/list";

/** Classify an upstream failure envelope into a shim-visible kind. */
function classifyUpstream(code, detail) {
	const text = String(detail ?? "");
	if (code === "110" || /daily count exceeded|daily limit/i.test(text)) return "hard_credit";
	if (code === "10605" || /queueType|isQueued/i.test(text)) return "soft_rate";
	if (code === "105" || /Login expired|TOKEN_EXPIRE|token is not active/i.test(text)) return "session_dead";
	if (/not found|no such model/i.test(text)) return "not_found";
	if (/invalid|bad request/i.test(text)) return "client";
	return "server";
}
function queueSeconds(text) {
	try {
		let node = JSON.parse(text);
		for (let depth = 0; depth < 4 && node != null && typeof node === "object"; depth++) {
			const seconds = node.retryAfterSeconds;
			if (typeof seconds === "number" && Number.isFinite(seconds)) return seconds;
			node = node.data ?? node.body ?? node.error;
		}
	} catch {}
	return 0;
}
/**
 * One upstream round trip: chat with the model, streaming OpenAI chunks.
 * Yields {chunk} values; throws {kind, message} on classified failures.
 */
async function* chatStream(credential, prepared, region, signal) {
	const url = `${region.baseUrl}${CHAT_PATH}?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`;
	const bodyText = JSON.stringify(prepared);
	const bodyBytes = encodeBody(bodyText);
	const headers = {
		...authHeaders(bodyBytes, url, credential),
		"Content-Type": "application/octet-stream",
	};
	let response;
	try {
		response = await fetch(url, { method: "POST", headers, body: bodyBytes, redirect: "error", signal });
	} catch (error) {
		if (signal?.aborted) throw { kind: "client", message: "aborted" };
		throw { kind: "soft_rate", message: `network error: ${String(error?.cause?.code ?? error?.message ?? error).slice(0, 200)}` };
	}
	if (!response.ok || response.body == null) {
		const text = await response.text().catch(() => "");
		throw { kind: classifyUpstream(void 0, text), message: `upstream http ${response.status}: ${text.slice(0, 300)}` };
	}
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let buffer = "";
	async function* frames() {
		while (true) {
			const { done, value } = await reader.read();
			if (done) return;
			buffer += decoder.decode(value, { stream: true });
			let idx;
			while ((idx = buffer.indexOf("\n")) >= 0) {
				const line = buffer.slice(0, idx).trimEnd();
				buffer = buffer.slice(idx + 1);
				if (line.startsWith("data:")) yield line.slice(5).trim();
			}
		}
	}
	/** Deep-unwrap a failure envelope to {code, detail}. */
	function unwrapFailure(node) {
		let code, detail;
		let current = node;
		for (let depth = 0; depth < 6 && current != null && typeof current === "object"; depth++) {
			code = current.errorCode ?? current.code ?? code;
			const message = current.errorMessage ?? current.message ?? current.detail ?? current.error;
			if (typeof message === "string") detail = message;
			current = current.data ?? current.body ?? current.error ?? current.result;
		}
		return { code: code === void 0 ? void 0 : String(code), detail };
	}
	for await (const payload of frames()) {
		if (payload === "" || payload === "[DONE]") continue;
		let envelope;
		try {
			envelope = JSON.parse(payload);
		} catch {
			continue;
		}
		let chunk = envelope;
		if (typeof envelope?.body === "string") {
			try {
				chunk = JSON.parse(envelope.body);
			} catch {
				continue;
			}
		} else if (envelope?.body !== void 0 && typeof envelope.body === "object") {
			chunk = envelope.body;
		}
		if (chunk == null || typeof chunk !== "object") continue;
		const hasChoices = chunk.choices != null;
		const hasUsage = chunk.usage != null && typeof chunk.usage === "object";
		if (hasChoices || hasUsage) {
			yield { chunk };
			continue;
		}
		const hasCode = chunk.code != null || chunk.errorCode != null;
		const hasMessage = typeof chunk.message === "string" && chunk.message !== "" || typeof chunk.errorMessage === "string" && chunk.errorMessage !== "";
		if (hasCode || hasMessage) {
			const { code, detail } = unwrapFailure(chunk);
			const kind = classifyUpstream(code, detail);
			const seconds = kind === "soft_rate" || kind === "hard_credit" ? queueSeconds(JSON.stringify(chunk)) : 0;
			const suffix = seconds > 0 ? ` (retry after ~${seconds}s)` : "";
			throw { kind, message: `upstream ${kind}${suffix}: ${String(detail ?? code ?? "unknown").slice(0, 300)}` };
		}
		// Unrecognised frame (statistics etc.) — skip.
	}
}
/** Fetch the live model catalog. Returns normalised model rows. */
async function fetchModelCatalog(credential, region, signal) {
	const url = `${region.baseUrl}${MODELS_PATH}?Encode=1`;
	const bodyBytes = encodeBody("");
	const headers = authHeaders(bodyBytes, url, credential);
	const response = await fetch(url, { method: "GET", headers, redirect: "error", signal });
	if (!response.ok) {
		const text = await response.text().catch(() => "");
		throw new Error(`model list http ${response.status}: ${text.slice(0, 200)}`);
	}
	const data = await response.json();
	if (data === null || typeof data !== "object" || Array.isArray(data) || !("chat" in data)) {
		throw new Error(`model list shape changed; top-level groups: ${data && typeof data === "object" ? Object.keys(data).slice(0, 8).join(", ") : typeof data}`);
	}
	const rows = [];
	for (const raw of data.chat) {
		if (raw === null || typeof raw !== "object") continue;
		const key = raw.key;
		if (typeof key !== "string" || key === "") continue;
		if (raw.enable === false) continue;
		rows.push({
			id: key,
			displayName: typeof raw.display_name === "string" && raw.display_name !== "" ? raw.display_name : key,
			supportsImages: raw.is_vl === true,
			isReasoning: raw.is_reasoning === true,
			free: raw.price_factor === 0,
			maxInputTokens: typeof raw.max_input_tokens === "number" && Number.isFinite(raw.max_input_tokens) ? raw.max_input_tokens : void 0,
		});
	}
	return rows;
}
//#endregion


/**
 * Prepare an OpenAI-shaped inbound body for the Qoder upstream.
 * Streaming is forced; `enable_thinking: false` is dropped because
 * alwaysThinking models (GLM-5.3-Flash, Kimi-K3…) reject it with provider
 * error 1210.
 */
function prepareChatBody(raw) {
	let parsed;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new Error("request body is not valid JSON");
	}
	if (parsed === null || typeof parsed !== "object" || typeof parsed.model !== "string" || !Array.isArray(parsed.messages)) {
		throw new Error("request body is not an OpenAI chat-completions object");
	}
	if (parsed.enable_thinking !== true) delete parsed.enable_thinking;
	parsed.stream = true;
	return parsed;
}
//#endregion


//#region openapi surface (plain bearer, no COSY)
/** OpenAPI hosts use a plain bearer token — no COSY signing, no body encoding. */
function openApiHeaders(credential) {
	return {
		Accept: "application/json",
		Authorization: `Bearer ${credential.token}`,
		"Cosy-Clienttype": "10",
		"User-Agent": "Qoder",
	};
}
const USERINFO_PATH = "/api/v1/userinfo";
const USAGE_PATH = "/api/v2/quota/usage";
const USAGE_PRESENTATION_PATH = "/sash/api/v2/me/usage";
const CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns";
function userInfoUrl(region) { return `${region.openApiUrl}${USERINFO_PATH}`; }
function usageUrl(region) { return `${region.openApiUrl}${USAGE_PATH}`; }
function usagePresentationUrl(region) { return `${region.openApiUrl}${USAGE_PRESENTATION_PATH}`; }
function campaignsUrl(region) { return `${region.openApiUrl}${CAMPAIGNS_PATH}`; }
function claimCampaignUrl(region, campaignId) { return `${region.openApiUrl}${CAMPAIGNS_PATH}/${encodeURIComponent(campaignId)}/claim`; }
async function readJson(response, context) {
	const text = await response.text().catch(() => "");
	try {
		return JSON.parse(text);
	} catch {
		throw new Error(`${context}: non-JSON response (${response.headers.get("content-type") ?? "no content-type"}): ${text.slice(0, 300)}`);
	}
}
/** Daily check-in campaigns (CLAIM_BENEFIT rows carry the credit grant). */
async function fetchCampaigns(credential, region, signal) {
	const response = await fetch(campaignsUrl(region), { headers: openApiHeaders(credential), redirect: "error", signal });
	if (!response.ok) throw new Error(`Qoder campaigns failed: HTTP ${response.status} ${(await response.text().catch(() => "")).slice(0, 200)}`);
	return await readJson(response, "Qoder campaigns");
}
/** Claim one campaign. The upstream is idempotent (replayed:true when already claimed). */
async function claimCampaign(credential, region, campaignId, signal) {
	const response = await fetch(claimCampaignUrl(region, campaignId), {
		method: "POST",
		headers: { ...openApiHeaders(credential), "Content-Type": "application/json" },
		body: "{}",
		redirect: "error",
		signal,
	});
	if (!response.ok) throw new Error(`Qoder check-in failed: HTTP ${response.status} ${(await response.text().catch(() => "")).slice(0, 200)}`);
	return await readJson(response, "Qoder check-in");
}
/** Quota + campaigns for the account, presentation shape first. */
async function fetchUsage(credential, region, signal) {
	let usage;
	let source = "presentation";
	try {
		const response = await fetch(usagePresentationUrl(region), { headers: openApiHeaders(credential), redirect: "error", signal });
		if (response.ok) usage = await readJson(response, "Qoder usage");
		else source = "quota";
	} catch (error) {
		if (signal?.aborted) throw error;
		source = "quota";
	}
	if (usage === void 0) {
		const response = await fetch(usageUrl(region), { headers: openApiHeaders(credential), redirect: "error", signal });
		if (!response.ok) throw new Error(`Qoder usage failed: HTTP ${response.status}`);
		usage = await readJson(response, "Qoder usage");
	}
	const record = (usage && typeof usage === "object" ? usage.qoderUsage ?? usage.data ?? usage : usage) ?? {};
	const userQuota = normalizeQuotaBucketAllowZero(record.user_quota ?? record.userQuota);
	const addOnQuota = normalizeQuotaBucketAllowZero(record.add_on_quota ?? record.addOnQuota);
	const rawPackages = record.dedicatedResourcePackages ?? record.dedicated_resource_packages;
	const dedicatedPackages = Array.isArray(rawPackages) ? rawPackages.map(normalizeDedicatedPackage).filter((p) => p !== void 0) : [];
	if (userQuota === void 0 && addOnQuota === void 0 && dedicatedPackages.length === 0) return void 0;
	const totalPercentage = Number(record.total_usage_percentage ?? record.totalUsagePercentage);
	return {
		displayMode: "qoder",
		userType: typeof record.user_type === "string" ? record.user_type : typeof record.userType === "string" ? record.userType : void 0,
		expiresAt: toEpochMs(record.expires_at ?? record.expiresAt),
		upgradeUrl: typeof record.upgrade_url === "string" ? record.upgrade_url : typeof record.upgradeUrl === "string" ? record.upgradeUrl : void 0,
		userQuota,
		addOnQuota,
		dedicatedPackages,
		totalUsagePercentage: Number.isFinite(totalPercentage) ? totalPercentage : void 0,
		isQuotaExceeded: record.is_quota_exceeded === true || record.isQuotaExceeded === true,
		source,
	};
}
/** Whether the desktop session is still accepted by the OpenAPI host. */
async function fetchUserInfo(credential, region, signal) {
	const response = await fetch(userInfoUrl(region), { headers: openApiHeaders(credential), redirect: "error", signal });
	if (!response.ok) throw new Error(`Qoder userinfo failed: HTTP ${response.status}`);
	return await readJson(response, "Qoder userinfo");
}
//#endregion

//#region claim / usage / offpeak pure functions
/** number<=1e12 = seconds, >1e12 = ms; string via Date.parse. */
function toEpochMs(value) {
	if (typeof value === "number" && Number.isFinite(value)) return value > 0 && value <= 1e12 ? value * 1e3 : value > 1e12 ? value : void 0;
	if (typeof value === "string") {
		const parsed = Date.parse(value);
		return Number.isFinite(parsed) && parsed > 0 ? parsed : void 0;
	}
	return void 0;
}
function benefitOf(campaign) {
	const amount = Number(campaign?.benefit?.amount);
	if (!Number.isFinite(amount) || amount <= 0) return void 0;
	const days = Number(campaign.benefit?.validity?.days);
	return { amount, kind: "CREDITS", validDays: Number.isFinite(days) && days > 0 ? days : void 0 };
}
function windowOpenAt(campaign, nowMs) {
	const start = toEpochMs(campaign?.startAt ?? campaign?.beginAt);
	const end = toEpochMs(campaign?.endAt);
	if (start !== void 0 && nowMs < start) return false;
	if (end !== void 0 && nowMs > end) return false;
	return true;
}
/** First CLAIM_BENEFIT campaign whose window is open (the daily credit grant). */
function claimableCampaignOf(payload, nowMs = Date.now()) {
	const rows = payload?.campaigns;
	if (!Array.isArray(rows)) return void 0;
	for (const campaign of rows) {
		if (campaign == null || typeof campaign !== "object") continue;
		if (campaign.actionType !== "CLAIM_BENEFIT") continue;
		if (!windowOpenAt(campaign, nowMs)) continue;
		return campaign;
	}
	return void 0;
}
function campaignIsClaimed(campaign) {
	return campaign?.claimStatus === "CLAIMED";
}
function checkinStateFrom(payload, nowMs = Date.now()) {
	const campaign = claimableCampaignOf(payload, nowMs);
	if (campaign === void 0) return { active: false, todayCheckedIn: false };
	const benefit = benefitOf(campaign);
	const unit = benefit?.kind === "CREDITS" ? "credits" : benefit?.kind ? String(benefit.kind).toLowerCase() : void 0;
	return {
		active: true,
		todayCheckedIn: campaignIsClaimed(campaign),
		amount: campaignIsClaimed(campaign) ? benefit?.amount : void 0,
		unit,
		validDays: benefit?.validDays,
		endsAt: toEpochMs(campaign.endAt),
	};
}
function normalizeClaimResult(payload, campaign) {
	const body = payload?.data ?? payload ?? {};
	const replayed = body.replayed === true;
	const status = body.status;
	const amount = Number(body.amount ?? benefitOf(campaign)?.amount);
	const granted = status === "CLAIMED" || replayed || body.success === true;
	return {
		claimed: granted,
		replayed,
		amount: !replayed && Number.isFinite(amount) && amount > 0 ? amount : void 0,
		expiresAt: toEpochMs(body.expiresAt),
	};
}
function quotaAmountsOf(source, total) {
	const used = Number(source?.used);
	const remainingRaw = Number(source?.remaining);
	const percentageRaw = Number(source?.percentage);
	const usedValue = Number.isFinite(used) ? Math.max(0, used) : 0;
	const remaining = Number.isFinite(remainingRaw) ? Math.max(0, remainingRaw) : Math.max(0, total - usedValue);
	const percentage = Number.isFinite(percentageRaw) ? (percentageRaw > 1 ? percentageRaw / 100 : percentageRaw) : total > 0 ? usedValue / total : 0;
	const unit = typeof source?.unit === "string" && source.unit !== "" ? source.unit : "credits";
	return { total, used: usedValue, remaining, percentage: Math.min(1, Math.max(0, percentage)), unit };
}
function normalizeQuotaBucket(source) {
	if (source == null || typeof source !== "object") return void 0;
	const total = Number(source.total);
	if (!Number.isFinite(total) || total <= 0) return void 0;
	return quotaAmountsOf(source, total);
}
/**
 * A bucket whose total is 0 carries no information (personal_standard accounts
 * have userQuota 0/0/0 and a funded addOnQuota), so it must not be dropped by
 * the total>0 rule — but it must not be presented as the main bucket either.
 */
function normalizeQuotaBucketAllowZero(source) {
	if (source == null || typeof source !== "object") return void 0;
	const total = Number(source.total);
	if (!Number.isFinite(total) || total < 0) return void 0;
	return quotaAmountsOf(source, total);
}
function normalizeDedicatedPackage(source) {
	if (source == null || typeof source !== "object") return void 0;
	const total = Number(source.total);
	if (typeof source.id !== "string" || source.id === "") return void 0;
	if (!Number.isFinite(total) || total <= 0) return void 0;
	return {
		id: source.id,
		name: typeof source.name === "string" ? source.name : void 0,
		description: typeof source.description === "string" ? source.description : void 0,
		...quotaAmountsOf(source, total),
		expiresAt: toEpochMs(source.expires_at ?? source.expiresAt),
		available: source.available !== false,
	};
}
/** USAGE-placement campaign rows for the panel. */
function projectCampaignRows(payload) {
	const rows = payload?.campaigns;
	if (!Array.isArray(rows)) return [];
	const out = [];
	for (const campaign of rows) {
		if (campaign == null || typeof campaign !== "object") continue;
		const placements = Array.isArray(campaign.placements) ? campaign.placements : [];
		if (!placements.some((placement) => placement?.type === "USAGE")) continue;
		const content = campaign.content;
		const title = typeof content?.zh === "string" ? content.zh : typeof content?.["zh-CN"] === "string" ? content["zh-CN"] : typeof content?.en === "string" ? content.en : void 0;
		const description = typeof campaign.description?.zh === "string" ? campaign.description.zh : typeof campaign.description?.en === "string" ? campaign.description.en : void 0;
		out.push({
			key: typeof campaign.campaignKey === "string" ? campaign.campaignKey : typeof campaign.campaignId === "string" ? campaign.campaignId : void 0,
			title,
			description,
			detailUrl: typeof campaign.detailUrl === "string" ? campaign.detailUrl : void 0,
			endsAt: toEpochMs(campaign.endAt),
		});
	}
	return out;
}
function localSecondsOf(date, timezone) {
	try {
		const parts = new Intl.DateTimeFormat("en-US", { timeZone: timezone, hourCycle: "h23", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(date);
		const get = (type) => Number(parts.find((part) => part.type === type)?.value ?? "0");
		const h = get("hour"), m = get("minute"), s = get("second");
		if (![h, m, s].every((n) => Number.isFinite(n))) return void 0;
		return h * 3600 + m * 60 + s;
	} catch {
		return void 0;
	}
}
function parseClock(text) {
	const match = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(String(text ?? ""));
	if (match === null) return void 0;
	const h = Number(match[1]), m = Number(match[2]), s = Number(match[3] ?? "0");
	if (h > 23 || m > 59 || s > 59) return void 0;
	return h * 3600 + m * 60 + s;
}
/** Windows crossing midnight (22:00-08:00) use disjunction. */
function windowIsOpen(windowStart, windowEnd, timezone, now = new Date()) {
	if (windowStart === void 0 || windowEnd === void 0 || windowStart === windowEnd) return false;
	const seconds = localSecondsOf(now, timezone);
	if (seconds === void 0) return false;
	return windowStart < windowEnd ? seconds >= windowStart && seconds < windowEnd : seconds >= windowStart || seconds < windowEnd;
}
/**
 * "Is this promotion still valid" — NOT "is the discount live now".
 * `promotion.active` is the instantaneous discount state: outside the window
 * it is false and carries no information. Only an OPEN window reporting false
 * means the campaign was killed.
 */
function promotionEnabled(promotion, now = new Date()) {
	if (promotion == null || typeof promotion !== "object") return false;
	if (promotion.active === true) return true;
	if (promotion.active === false) {
		const start = parseClock(promotion.window_start);
		const end = parseClock(promotion.window_end);
		if (start !== void 0 && end !== void 0) return !windowIsOpen(start, end, typeof promotion.timezone === "string" ? promotion.timezone : "Asia/Shanghai", now);
	}
	return false;
}
/** Is the off-peak discount live right now (needs active===true AND an open window). */
function isOffPeakActive(entry, now = new Date()) {
	const promotion = entry?.promotion;
	if (promotion == null || typeof promotion !== "object" || promotion.active !== true) return false;
	const start = parseClock(promotion.window_start);
	const end = parseClock(promotion.window_end);
	if (start === void 0 || end === void 0) return false;
	return windowIsOpen(start, end, typeof promotion.timezone === "string" ? promotion.timezone : "Asia/Shanghai", now);
}
function effectiveRate(entry, now = new Date()) {
	const promotion = entry?.promotion;
	if (isOffPeakActive(entry, now)) {
		const before = Number(promotion.before_promotion_price_factor);
		const discount = Number(promotion.discount_factor);
		if (Number.isFinite(before) && Number.isFinite(discount)) return before * discount;
		if (Number.isFinite(before)) return before;
	}
	if (Number.isFinite(Number(promotion?.before_promotion_price_factor))) return Number(promotion.before_promotion_price_factor);
	return Number.isFinite(Number(entry?.price_factor)) ? Number(entry.price_factor) : void 0;
}
/** Seconds until the promotion flips state (86400 wrap). */
function offPeakRemaining(entry, now = new Date()) {
	const promotion = entry?.promotion;
	if (promotion == null || typeof promotion !== "object") return 0;
	const start = parseClock(promotion.window_start);
	const end = parseClock(promotion.window_end);
	if (start === void 0 || end === void 0) return 0;
	const timezone = typeof promotion.timezone === "string" ? promotion.timezone : "Asia/Shanghai";
	const seconds = localSecondsOf(now, timezone);
	if (seconds === void 0) return 0;
	const active = windowIsOpen(start, end, timezone, now);
	const flip = active ? end : start;
	const delta = flip - seconds;
	return delta > 0 ? delta : delta + 86400;
}
//#endregion

const NO_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
const DEFAULT_MAX_TOKENS = 32768;
/** One live model row as served to the pickers and the shim. */
function normalizeCatalogRow(raw) {
	return {
		id: raw.id,
		name: raw.free ? `${raw.displayName}（免费）` : raw.displayName,
		supportsImages: raw.supportsImages,
		reasoning: raw.isReasoning,
		contextWindow: raw.maxInputTokens ?? 200000,
		maxTokens: DEFAULT_MAX_TOKENS,
	};
}
class QoderCatalog {
	constructor() {
		this.models = [];
		this.visible = false;
	}
	current() {
		return this.models;
	}
	set(models) {
		this.models = models;
	}
	setVisible(visible) {
		if (this.visible === visible) return false;
		this.visible = visible;
		return true;
	}
	isVisible() {
		return this.visible;
	}
}
//#endregion


export { DEFAULT_MAX_TOKENS, NO_COST, QoderCatalog, campaignIsClaimed, campaignsUrl, chatStream, checkinStateFrom, claimCampaign, claimableCampaignOf, classifyUpstream, effectiveRate, encodeBody, fetchCampaigns, fetchModelCatalog, fetchUsage, fetchUserInfo, isOffPeakActive, normalizeCatalogRow, normalizeClaimResult, normalizeQuotaBucket, normalizeQuotaBucketAllowZero, offPeakRemaining, openApiHeaders, prepareChatBody, projectCampaignRows, promotionEnabled, quotaAmountsOf, toEpochMs, usagePresentationUrl, usageUrl, userInfoUrl };
