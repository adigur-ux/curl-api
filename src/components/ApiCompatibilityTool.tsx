"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

type CaseType = "A" | "B" | "C";

type Package = {
	id: number;
	name: string;
	credits: number;
	description: string;
	price_usd: number;
	sort_order: number;
};

type PackagesResponse = {
	packages: Package[];
};

type ZapierResponse = {
	summary: string;
	issues: string[];
	fixed_curl: string | null;
	diagnosis: string | null;
	recommendation: string | null;
	headers_to_change: string[];
	body_mapping: string[];
	missing_info: boolean;
};

/**
 * Configuration constants. Replace placeholders with your real values.
 */
const ZAP_A_WEBHOOK_URL = process.env.NEXT_PUBLIC_ZAP_A_WEBHOOK_URL || "https://hooks.zapier.com/hooks/catch/20378221/u1j9fqy/";
const ZAP_B_WEBHOOK_URL = process.env.NEXT_PUBLIC_ZAP_B_WEBHOOK_URL || "https://hooks.zapier.com/hooks/catch/20378221/u9bxdj0/";
const ZAP_C_WEBHOOK_URL = process.env.NEXT_PUBLIC_ZAP_C_WEBHOOK_URL || "https://hooks.zapier.com/hooks/catch/20378221/u9mt13t/";

const XANO_BASE_URL = process.env.NEXT_PUBLIC_XANO_BASE_URL || "https://x8ki-letl-twmt.n7.xano.io/api:oNjZ-H43";
const XANO_LOGIN_PATH = "/auth/login";
const XANO_SIGNUP_PATH = "/auth/signup";
const XANO_ME_PATH = "/auth/me";
const XANO_ME_PASS = "/auth/pass";
const XANO_PACKAGES_PATH = "https://x8ki-letl-twmt.n7.xano.io/api:RMcckRv2/Package"; // You'll need to fill this endpoint manually

const FREE_TRIAL_REQUESTS = Number(process.env.NEXT_PUBLIC_FREE_TRIAL_REQUESTS || 1);

const PAYPAL_CLIENT_ID_SANDBOX = process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID || "AUUfKzqKpeBefE07Z8kDrgeRO-YcROw-t-k3SnXdfkOf8oVyiVdHeh65yWP1v5aqYfrBd4oYY_x2ShPO";
const PAYPAL_PLAN_ID = process.env.NEXT_PUBLIC_PAYPAL_PLAN_ID || ""; // Optional. If set, will use subscription flow

const ADMIN_SUPPORT_EMAIL = "admin_support@heal-api.com";

const LS_KEYS = {
	freeTrialUsed: "api-compat-freeTrialUsed",
	authToken: "api-compat-xanoToken",
	unlimited: "api-compat-unlimited",
};

function classNames(...classes: Array<string | false | null | undefined>) {
	return classes.filter(Boolean).join(" ");
}

function formatJson(value: unknown): string {
	try {
		return JSON.stringify(value, null, 2);
	} catch {
		return String(value);
	}
}

function downloadTextAsFile(filename: string, content: string) {
	const blob = new Blob([content], { type: "application/json" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}

function downloadPptxTutorial() {
	// Create a link to download the PPTX tutorial
	const link = document.createElement("a");
	link.href = "/tutorial.pptx"; // This will be the path to your PPTX file
	link.download = "API_Compatibility_Tutorial.pptx";
	link.click();
}

async function copyToClipboard(text: string) {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
}

function generateShareLinkPlaceholder(): string {
	const id = Math.random().toString(36).slice(2);
	return `https://example.com/share/${id}`;
}

function openEmailClient(email: string, subject?: string, body?: string) {
	// Create web email URLs
	const gmailUrl = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(email)}&su=${encodeURIComponent(subject || 'Support Request')}&body=${encodeURIComponent(body || '')}`;
	const outlookUrl = `https://outlook.live.com/mail/0/deeplink/compose?to=${encodeURIComponent(email)}&subject=${encodeURIComponent(subject || 'Support Request')}&body=${encodeURIComponent(body || '')}`;
	
	// Try mailto first
	try {
		const params = new URLSearchParams();
		if (subject) params.append('subject', subject);
		if (body) params.append('body', body);
		const mailtoUrl = `mailto:${email}${params.toString() ? '?' + params.toString() : ''}`;
		
		const link = document.createElement('a');
		link.href = mailtoUrl;
		link.style.display = 'none';
		document.body.appendChild(link);
		link.click();
		document.body.removeChild(link);
		
		// If mailto doesn't work, show web email options after a short delay
		setTimeout(() => {
			// Check if we're still on the same page (mailto didn't work)
			if (document.hasFocus()) {
				// Show web email options
				const choice = confirm(
					`No email client detected. Choose your preferred web email service:\n\n` +
					`• Click OK to open Gmail\n` +
					`• Click Cancel to open Outlook\n\n` +
					`Email: ${email}`
				);
				
				if (choice) {
					window.open(gmailUrl, '_blank');
				} else {
					window.open(outlookUrl, '_blank');
				}
			}
		}, 500);
		
	} catch (error) {
		// Fallback: show web email options immediately
		const choice = confirm(
			`Choose your preferred email service:\n\n` +
			`• Click OK to open Gmail (web-based)\n` +
			`• Click Cancel to open Outlook (web-based)\n\n` +
			`Email: ${email}`
		);
		
		if (choice) {
			window.open(gmailUrl, '_blank');
		} else {
			window.open(outlookUrl, '_blank');
		}
	}
}

function getPublicBaseUrl(): string {
	const fromEnv = process.env.NEXT_PUBLIC_PUBLIC_BASE_URL;
	if (fromEnv && fromEnv.trim().length > 0) return fromEnv.replace(/\/$/, "");
	if (typeof window !== "undefined" && window.location?.origin) return window.location.origin;
	return "";
}

type AuthMode = "login" | "signup";

type AuthResult = {
	token: string;
	creditsRemaining?: number | null;
};

async function xanoAuth(
	mode: AuthMode,
	email: string,
	password: string,
	name?: string
): Promise<AuthResult> {
	const endpoint = `${XANO_BASE_URL}${mode === "login" ? XANO_LOGIN_PATH : XANO_SIGNUP_PATH}`;
	const body = mode === "login" 
		? { email, password }
		: { email, password, name: name || "" };
	const res = await fetch(endpoint, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	if (!res.ok) {
		throw new Error("Authentication failed - Sign in to continue");
	}
	const data = (await res.json()) as { authToken?: string; token?: string };
	const token = (data as any).authToken || (data as any).token;
	if (!token) {
		throw new Error("No token returned by Xano");
	}
	return { token, creditsRemaining: null };
}

function useLocalStorageNumber(key: string, defaultValue: number) {
	const [value, setValue] = useState<number>(() => {
		const raw = typeof window !== "undefined" ? localStorage.getItem(key) : null;
		const parsed = raw != null ? Number(raw) : NaN;
		return Number.isFinite(parsed) ? parsed : defaultValue;
	});
	useEffect(() => {
		localStorage.setItem(key, String(value));
	}, [key, value]);
	return [value, setValue] as const;
}

function useLocalStorageBoolean(key: string, defaultValue: boolean) {
	const [value, setValue] = useState<boolean>(() => {
		const raw = typeof window !== "undefined" ? localStorage.getItem(key) : null;
		if (raw === null) return defaultValue;
		return raw === "true";
	});
	useEffect(() => {
		localStorage.setItem(key, String(value));
	}, [key, value]);
	return [value, setValue] as const;
}

function useLocalStorageString(key: string, defaultValue: string) {
	const [value, setValue] = useState<string>(() => {
		const raw = typeof window !== "undefined" ? localStorage.getItem(key) : null;
		return raw != null ? raw : defaultValue;
	});
	useEffect(() => {
		localStorage.setItem(key, value);
	}, [key, value]);
	return [value, setValue] as const;
}

function usePayPalButtons(options: { clientId: string; planId?: string; enableButtons?: boolean; onApprove?: () => void; selectedPackage?: Package | null }) {
	const [isReady, setIsReady] = useState(false);
	const containerRef = useRef<HTMLDivElement | null>(null);

	useEffect(() => {
		if (!options.clientId) return;
		
		const existing = document.querySelector<HTMLScriptElement>("script#paypal-sdk");
		if (existing) {
			setIsReady(true);
			return;
		}
		
		const script = document.createElement("script");
		script.id = "paypal-sdk";
		const base = "https://www.paypal.com/sdk/js";
		const params = new URLSearchParams({
			"client-id": options.clientId,
			components: "buttons",
			currency: "USD",
			intent: options.planId ? "subscription" : "capture",
			vault: options.planId ? "true" : "false",
			locale: "he_IL",
		});
		script.src = `${base}?${params.toString()}`;
		script.async = true;
		script.onload = () => setIsReady(true);
		document.body.appendChild(script);
	}, [options.clientId, options.planId]);

	useEffect(() => {
		if (!options.enableButtons || !isReady || !containerRef.current) return;
		
		const container = containerRef.current;
		container.innerHTML = "";
		const w = window as any;
		
		if (!w.paypal?.Buttons) return;
		
		const buttons = w.paypal.Buttons({
			style: { layout: "vertical", color: "gold", shape: "rect", label: "subscribe" },
			createSubscription: options.planId
				? function (data: any, actions: any) {
					return actions.subscription.create({ plan_id: options.planId });
				}
				: undefined,
			createOrder: !options.planId
				? function (_data: any, actions: any) {
					const price = options.selectedPackage?.price_usd?.toFixed(2) || "5.00";
					return actions.order.create({ purchase_units: [{ amount: { value: price } }] });
				}
				: undefined,
			onApprove: function (data: any, actions: any) {
				return actions.order.capture().then(async function (details: any) {
					console.log('PayPal order captured:', details);
					
					// Extract transaction data from PayPal details
					const orderId = details.id;
					const priceUsd = parseFloat(details.purchase_units[0]?.payments?.captures[0]?.amount?.value || '0');
					const status = details.status;
					const email = details.payer?.email_address || '';
					
					// Get package info from selected package
					const packageId = options.selectedPackage?.id || 0;
					const credits = options.selectedPackage?.credits || 0;
					
					// Call Xano transaction API
					try {
						const response = await fetch('https://x8ki-letl-twmt.n7.xano.io/api:RMcckRv2/Transaction', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
							},
							body: JSON.stringify({
								order_id: orderId,
								price_usd: priceUsd,
								package_id: packageId,
								credits: credits,
								status: status,
								email: email
							})
						});
						
						if (response.ok) {
							console.log('Transaction recorded in Xano successfully');
							// Refresh the page to fetch updated daily quota
							window.location.reload();
						} else {
							console.error('Failed to record transaction in Xano:', response.statusText);
						}
					} catch (error) {
						console.error('Error calling Xano transaction API:', error);
					}
				});
			},
		});
		buttons.render(container);
		return () => {
			try {
				buttons.close();
			} catch {}
		};
	}, [isReady, containerRef.current, options.enableButtons, options.clientId, options.planId, options.onApprove, options.selectedPackage]);

	return { isReady, containerRef } as const;
}

export default function ApiCompatibilityTool() {
	const [caseType, setCaseType] = useState<CaseType>("A");
	const [mounted, setMounted] = useState(false);
	useEffect(() => setMounted(true), []);

	const [providerUrl, setProviderUrl] = useState("");
	const [consumerUrl, setConsumerUrl] = useState("");
	const [userCurl, setUserCurl] = useState("");
	const [failureReason, setFailureReason] = useState("");
	const [taskExplanation, setTaskExplanation] = useState("");
	const [fixedCurl, setFixedCurl] = useState("");

	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<ZapierResponse | null>(null);
	const [pendingRequestId, setPendingRequestId] = useState<string | null>(null);
	const [timeoutActive, setTimeoutActive] = useState(false);
	const [timeRemaining, setTimeRemaining] = useState(0);

	const [freeUsed, setFreeUsed] = useLocalStorageNumber(LS_KEYS.freeTrialUsed, 0);
	const freeRemaining = Math.max(FREE_TRIAL_REQUESTS - freeUsed, 0);

	const [authToken, setAuthToken] = useLocalStorageString(LS_KEYS.authToken, "");
	const isAuthenticated = Boolean(authToken);
	const [showAuthModal, setShowAuthModal] = useState(false);
	const [authMode, setAuthMode] = useState<AuthMode>("login");
	const [authName, setAuthName] = useState("");
	// Replace authEmail state with localStorage-backed version
	const [authEmail, setAuthEmail] = useLocalStorageString('api-compat-authEmail', "");
	const [authPassword, setAuthPassword] = useState("");
	const [isAuthLoading, setIsAuthLoading] = useState(false);
	const [authError, setAuthError] = useState<string | null>(null);
	const [authNotice, setAuthNotice] = useState<string | null>(null);
	const [showTermsModal, setShowTermsModal] = useState(false);
	const [agreedToTerms, setAgreedToTerms] = useState(false);
	const [showContactModal, setShowContactModal] = useState(false);
	const [showEmailServiceModal, setShowEmailServiceModal] = useState(false);
	const [hasTriedToRun, setHasTriedToRun] = useLocalStorageBoolean("api-compat-hasTriedToRun", false);

	const [remainingCredits, setRemainingCredits] = useState<number | null>(null);
	const [hasUnlimited, setHasUnlimited] = useLocalStorageBoolean(LS_KEYS.unlimited, false);

	// Package selection state
	const [packages, setPackages] = useState<Package[]>([]);
	const [selectedPackage, setSelectedPackage] = useState<Package | null>(null);
	const [showPackageModal, setShowPackageModal] = useState(false);
	const [isLoadingPackages, setIsLoadingPackages] = useState(false);
	const [showPolicyModal, setShowPolicyModal] = useState(false);
	const [showProviderTooltip, setShowProviderTooltip] = useState(false);
	const [showConsumerTooltip, setShowConsumerTooltip] = useState(false);
	const [showCurlHelpTooltip, setShowCurlHelpTooltip] = useState(false);
	const [showFailureReasonHelpTooltip, setShowFailureReasonHelpTooltip] = useState(false);

	// Add a constant for inactivity timeout (1 hour)
	const INACTIVITY_TIMEOUT_MS = 60 * 60 * 1000; // 1 hour
	const LS_LAST_ACTIVE = 'api-compat-lastActive';

	// Helper to update last active timestamp
	function updateLastActive() {
		if (typeof window !== 'undefined') {
			localStorage.setItem(LS_LAST_ACTIVE, Date.now().toString());
		}
	}

	// Helper to check if session is expired
	function isSessionExpired() {
		if (typeof window === 'undefined') return true;
		const lastActive = localStorage.getItem(LS_LAST_ACTIVE);
		if (!lastActive) return true;
		return Date.now() - Number(lastActive) > INACTIVITY_TIMEOUT_MS;
	}

	// On mount, check for session expiration
	useEffect(() => {
		if (isAuthenticated && isSessionExpired()) {
			// Session expired, force logout
			setAuthToken("");
			setAuthEmail("");
			setShowAuthModal(true);
		}
		// If not authenticated, show login modal
		if (!isAuthenticated) {
			setShowAuthModal(true);
		}
	}, []); // Only run on mount

	// Function to fetch credits from Xano
	const fetchCreditsFromXano = async () => {
		updateLastActive();
		if (!isAuthenticated || !authToken || !authEmail) {
			return;
		}
		try {
			const response = await fetch(`${XANO_BASE_URL}/auth/me_quota?email=${encodeURIComponent(authEmail)}`, {
				method: 'GET',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${authToken}`
				}
			});
			if (response.ok) {
				const data = await response.json();
				// Handle response: {"daily_quota":[{"daily_quota":2}]}
				if (Array.isArray(data.daily_quota) && data.daily_quota.length > 0 && typeof data.daily_quota[0].daily_quota === 'number') {
					setRemainingCredits(data.daily_quota[0].daily_quota);
				}
			}
		} catch (error) {
			// handle error
		}
	};

	// Function to update credits in Xano
	const updateCreditsInXano = async (newCreditCount: number) => {
		updateLastActive();
		if (!isAuthenticated || !authToken) {
			console.log('Cannot update credits: not authenticated or no token');
			return;
		}
		
		try {
			console.log('Updating credits in Xano:', newCreditCount);
			const response = await fetch(`${XANO_BASE_URL}${XANO_ME_PATH}`, {
				method: 'POST',
				headers: { 
					'Authorization': `Bearer ${authToken}`,
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ daily_quota: newCreditCount })
			});
			
			if (response.ok) {
				const result = await response.json();
				console.log('Credits updated in Xano successfully:', result);
				
				// Update the local state with the returned value
				if (result.user?.daily_quota !== undefined) {
					const credits = Number(result.user.daily_quota);
					if (!isNaN(credits)) {
						// Only update if the value is different from what we expect
						if (credits !== newCreditCount) {
							setRemainingCredits(credits);
						}
					} else {
						console.error('Invalid daily_quota value from Xano:', result.user.daily_quota);
						setRemainingCredits(2); // Fallback to default
					}
				} else {
					console.log('No daily_quota in response, keeping current value');
				}
			} else {
				const errorText = await response.text();
				console.error('Failed to update credits in Xano:', response.status, response.statusText, errorText);
			}
		} catch (error) {
			console.error('Error updating credits in Xano:', error);
		}
	};

	const fetchQuotaFromXano = async (email: string) => {
		try {
			const response = await fetch(`${XANO_BASE_URL}/auth/me_quota`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email }),
			});
			if (response.ok) {
				const data = await response.json();
				if (typeof data.daily_quota === 'number') {
					setRemainingCredits(data.daily_quota);
				}
			}
		} catch (err) {
			console.error('Failed to fetch daily_quota from Xano', err);
		}
	};

	// Function to fetch packages from Xano
	const fetchPackagesFromXano = async () => {
		setIsLoadingPackages(true);
		try {
			const response = await fetch(XANO_PACKAGES_PATH, {
				method: 'GET',
				headers: { 'Content-Type': 'application/json' }
			});
			if (response.ok) {
				const data: PackagesResponse = await response.json();
				// Sort packages by sort_order field
				const sortedPackages = data.packages.sort((a, b) => a.sort_order - b.sort_order);
				setPackages(sortedPackages);
			} else {
				console.error('Failed to fetch packages from Xano');
			}
		} catch (err) {
			console.error('Error fetching packages from Xano', err);
		} finally {
			setIsLoadingPackages(false);
		}
	};

	const canSubmit = useMemo(() => {
		if (!providerUrl || !consumerUrl) return false;
		if (caseType !== "C" && caseType !== "B" && !userCurl) return false;
		if (caseType === "B" && !failureReason) return false;
		return true;
	}, [providerUrl, consumerUrl, userCurl, failureReason, caseType]);

	const shouldGateOnAuthOrPayment = useMemo(() => {
		if (freeRemaining > 0 && hasTriedToRun) return false;
		if (!isAuthenticated) return true;
		if (hasUnlimited) return false;
		if (remainingCredits == null) return false;
		return remainingCredits <= 0;
	}, [freeRemaining, isAuthenticated, hasUnlimited, remainingCredits, hasTriedToRun]);

	const paypal = usePayPalButtons({ 
		clientId: PAYPAL_CLIENT_ID_SANDBOX, 
		planId: PAYPAL_PLAN_ID || undefined,
		enableButtons: shouldGateOnAuthOrPayment && isAuthenticated && !hasUnlimited && !!selectedPackage,
		selectedPackage: selectedPackage
	});

	const webhookUrl = useMemo(() => {
		if (caseType === "A") return "/api/zap/a";
		if (caseType === "B") return "/api/zap/b";
		return "/api/zap/c";
	}, [caseType]);


	const extractCurlString = useCallback((payload: any): string | null => {
		try {
			if (!payload) return null;
			const getStr = (v: any) => (typeof v === "string" && v.trim().length > 0 ? v : null);
			// Common direct locations
			const direct = getStr(payload.fixed_curl) || getStr(payload.curl);
			if (direct) return direct;
			// Under result
			const underResult = payload.result ? getStr(payload.result.fixed_curl) || getStr(payload.result.curl) : null;
			if (underResult) return underResult;
			// Deep search
			const stack: any[] = [payload];
			while (stack.length) {
				const current = stack.pop();
				if (current && typeof current === "object") {
					for (const key of Object.keys(current)) {
						const val = (current as any)[key];
						if ((key === "fixed_curl" || key === "curl") && getStr(val)) return val;
						if (val && typeof val === "object") stack.push(val);
					}
				}
			}
			return null;
		} catch {
			return null;
		}
	}, []);

	const displayedJson = useMemo(() => {
		if (!result) return null;
		// Case C: Handle both object and stringified curl_command in result.result
		if (caseType === "C") {
		  let curlStr: string | undefined = undefined;
		  const res = (result as any)?.result;
		  if (typeof res === "object" && res !== null && typeof res.curl_command === "string") {
			curlStr = res.curl_command;
		  } else if (typeof res === "string") {
			try {
			  const parsed = JSON.parse(res);
			  if (parsed && typeof parsed.curl_command === "string") {
				curlStr = parsed.curl_command;
			  } else {
				curlStr = res;
			  }
			} catch {
			  curlStr = res;
			}
		  }
		  return { curl_command: curlStr || "NO_CURL_COMMAND_FOUND" };
		}
		if (caseType === "A") {
		  const anyRes: any = result as any;
		  const fixed = result.fixed_curl || extractCurlString(anyRes) || "";
		  return { fixed_curl: fixed };
		}
		return result;
	}, [result, caseType, extractCurlString]);

const buildPayload = useCallback((): { payload: any; requestId: string } => {
		const callbackUrl = `${getPublicBaseUrl()}/api/zap/callback`;
		const common = { provider_url: providerUrl, consumer_url: consumerUrl };
		if (caseType === "A") {
			const requestId = crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
        const payload: any = { ...common, user_curl: userCurl, callback_url: callbackUrl, request_id: requestId };
			if (fixedCurl && fixedCurl.trim().length > 0) {
				payload.fixed_curl = fixedCurl;
			}
        return { payload, requestId };
		}
		if (caseType === "B") {
			const requestId = crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
			// For B: userCurl can be null if blank
			const userCurlOrNull = userCurl && userCurl.trim().length > 0 ? userCurl : null;
			const payload = { ...common, user_curl: userCurlOrNull, failure_reason: failureReason, callback_url: callbackUrl, request_id: requestId } as any;
			return { payload, requestId };
		}
		const requestId = crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    const payload = { ...common, task_explanation: taskExplanation, callback_url: callbackUrl, request_id: requestId } as any;
    return { payload, requestId };
	}, [providerUrl, consumerUrl, userCurl, failureReason, taskExplanation, fixedCurl, caseType]);

	const handleSubmit = useCallback(async () => {
		setError(null);
		setResult(null);
		if (!canSubmit) return;

		// Mark that user has tried to run a check
		setHasTriedToRun(true);

		// Require login on first attempt
		if (!hasTriedToRun && !isAuthenticated) {
			setShowAuthModal(true);
			return;
		}

		// Check authentication and credits
		if (!isAuthenticated) {
			setShowAuthModal(true);
			return;
		}
		
		if (freeRemaining <= 0 && !hasUnlimited && (remainingCredits ?? 0) <= 0) {
			return; // PayPal section visible below
		}

		setIsSubmitting(true);
		setTimeoutActive(true);
		setTimeRemaining(10);
		
		// Start countdown timer
		const countdownTimer = setInterval(() => {
			setTimeRemaining((prev) => {
				if (prev <= 1) {
					clearInterval(countdownTimer);
					setTimeoutActive(false);
					return 0;
				}
				return prev - 1;
			});
		}, 1000);

		try {
        const { payload, requestId } = buildPayload();
        setPendingRequestId(requestId);
        const res = await fetch(webhookUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
			});
			if (!res.ok) {
				throw new Error("Request failed");
			}
			// Case A might return only fixed_curl as a string; normalize
			let data: ZapierResponse;
			const raw = await res.text();
            try {
                const parsed = JSON.parse(raw);
				if (caseType === "A" && typeof parsed === "string") {
					data = {
						summary: "",
						issues: [],
						fixed_curl: parsed,
						diagnosis: null,
						recommendation: null,
						headers_to_change: [],
						body_mapping: [],
						missing_info: false,
					};
                } else if (
                    caseType === "A" &&
                    parsed &&
                    typeof parsed === "object" &&
                    ("curl" in (parsed as any) || "fixed_curl" in (parsed as any) || "result" in (parsed as any))
                ) {
                    // Support top-level curl/fixed_curl or nested result.{fixed_curl|curl}
                    const anyParsed: any = parsed as any;
                    let fc: string = anyParsed.fixed_curl || anyParsed.curl || "";
                    if (!fc && anyParsed.curl && typeof anyParsed.curl === "object") {
                        fc = anyParsed.curl.fixed_curl || anyParsed.curl.curl || "";
                    }
                    if (!fc && anyParsed.curl_fix && typeof anyParsed.curl_fix === "object") {
                        fc = anyParsed.curl_fix.fixed_curl || anyParsed.curl_fix.curl || "";
                    }
                    if (!fc && anyParsed.result) {
                        if (typeof anyParsed.result === "string") {
                            const rStr = anyParsed.result as string;
                            try {
                                const r = JSON.parse(rStr);
                                fc = r?.fixed_curl || r?.curl || "";
                            } catch {
                                const trimmed = rStr.trim();
                                if (trimmed.startsWith("curl")) {
                                    fc = trimmed;
                                } else {
                                    const match = rStr.match(/\"fixed_curl\"\s*:\s*\"([^\"]+)/);
                                    if (match && match[1]) fc = match[1];
                                }
                            }
                        } else if (typeof anyParsed.result === "object") {
                            fc = anyParsed.result.fixed_curl || anyParsed.result.curl || "";
                            if (!fc && anyParsed.result.curl && typeof anyParsed.result.curl === "object") {
                                fc = anyParsed.result.curl.fixed_curl || anyParsed.result.curl.curl || "";
                            }
                            if (!fc && anyParsed.result.curl_fix && typeof anyParsed.result.curl_fix === "object") {
                                fc = anyParsed.result.curl_fix.fixed_curl || anyParsed.result.curl_fix.curl || "";
                            }
                        }
                    }
					data = {
						summary: "",
						issues: [],
                        fixed_curl: fc,
						diagnosis: null,
						recommendation: null,
						headers_to_change: [],
						body_mapping: [],
						missing_info: false,
					};
				} else {
					data = parsed as ZapierResponse;
				}
			} catch {
				if (caseType === "A") {
					data = {
						summary: "",
						issues: [],
						fixed_curl: raw,
						diagnosis: null,
						recommendation: null,
						headers_to_change: [],
						body_mapping: [],
						missing_info: false,
					};
				} else {
					throw new Error("Invalid JSON response");
				}
			}
			
			// Wait for timeout to complete before showing result
			setTimeout(() => {
				setResult(data);
				clearInterval(countdownTimer);
				setTimeoutActive(false);
			}, 10000);
			
			// If callback is expected, start polling for enriched results keyed by request_id
            if (requestId) {
                let attempts = 0;
				const maxAttempts = 10;
				const intervalMs = 2000;
				let hasValidPayload = false;
				let pendingResult: ZapierResponse | null = null;
				let timeoutId: NodeJS.Timeout | null = null;
				
				const resetTimeout = () => {
					if (timeoutId) {
						clearTimeout(timeoutId);
					}
					setTimeoutActive(true);
					setTimeRemaining(10);
					
					// Start new countdown timer
					const newCountdownTimer = setInterval(() => {
						setTimeRemaining((prev) => {
							if (prev <= 1) {
								clearInterval(newCountdownTimer);
								return 0;
							}
							return prev - 1;
						});
					}, 1000);
					
					timeoutId = setTimeout(() => {
						if (hasValidPayload && pendingResult) {
							// Show the enriched result from polling
							setResult(pendingResult);
						} else {
							// Show the original result from the initial API call
							// (this will be the same as the data we already have)
						}
						clearInterval(timer);
						setPendingRequestId(null);
						clearInterval(newCountdownTimer);
						setTimeoutActive(false);
					}, 10000);
				};
				
				// Start initial timeout
				resetTimeout();
				
				const timer = setInterval(async () => {
					attempts += 1;
					try {
						const base = process.env.NEXT_PUBLIC_PUBLIC_BASE_URL as string;
						const pollRes = await fetch(`${base}api/zap/callback?request_id=${encodeURIComponent(requestId)}`, { cache: "no-store" });
						if (pollRes.ok) {
							const body = await pollRes.json();
							if (body?.found && body?.payload) {
								// We found a valid payload, process it but don't show yet
								hasValidPayload = true;
								const payload = body.payload;
								// Prefer canonical fixed_curl from payload or nested result
								let newResult: ZapierResponse | null = null;
								let fc: string | null = null;
								if (payload) {
									const direct = typeof payload.fixed_curl === "string" && payload.fixed_curl.trim().length > 0 ? payload.fixed_curl.trim() : null;
									let nested: string | null = null;
									const pr: unknown = (payload as any).result;
									if (!direct && pr) {
										if (typeof pr === "object" && pr !== null && typeof (pr as any).fixed_curl === "string" && (pr as any).fixed_curl.trim().length > 0) {
											nested = ((pr as any).fixed_curl as string).trim();
										} else if (typeof pr === "string") {
											try {
												const parsed = JSON.parse(pr);
												if (parsed && typeof parsed === "object" && typeof (parsed as any).fixed_curl === "string" && (parsed as any).fixed_curl.trim().length > 0) {
													nested = ((parsed as any).fixed_curl as string).trim();
												}
											} catch {}
										}
									}
									fc = direct || nested;
								}
                                if (fc || payload?.result) {
                                    let details: any = null;
                                    const pr: unknown = (payload as any).result;
                                    if (pr && typeof pr === "object") {
                                        details = pr as any;
                                    } else if (typeof pr === "string") {
                                        try {
                                            const parsed = JSON.parse(pr);
                                            if (parsed && typeof parsed === "object") {
                                                details = parsed as any;
                                            }
                                        } catch {}
                                    }

                                    pendingResult = {
                                        summary: (details?.summary as string) || "",
                                        issues: Array.isArray(details?.issues) ? (details.issues as string[]) : [],
                                        fixed_curl: fc || (typeof details?.fixed_curl === "string" ? (details.fixed_curl as string) : null),
                                        diagnosis: (details?.diagnosis as string) ?? null,
                                        recommendation: (details?.recommendation as string) ?? null,
                                        headers_to_change: Array.isArray(details?.headers_to_change) ? (details.headers_to_change as string[]) : [],
                                        body_mapping: Array.isArray(details?.body_mapping) ? (details.body_mapping as string[]) : [],
                                        missing_info: Boolean(details?.missing_info) || false,
                                    };
                                }
								// Stop polling once we have a valid payload
								clearInterval(timer);
							} else {
								// If body.payload is null, reset timeout for another 10 seconds
								resetTimeout();
							}
						}
					} catch {}
					if (attempts >= maxAttempts) {
						clearInterval(timer);
						setPendingRequestId(null);
						if (timeoutId) {
							clearTimeout(timeoutId);
						}
						setTimeoutActive(false);
					}
				}, intervalMs);
			}
			// Deduct credits based on what's available
			if (isAuthenticated && !hasUnlimited && remainingCredits !== null && remainingCredits > 0) {
				// User is authenticated, deduct from their credits
				const newCreditCount = remainingCredits - 1;
				
				// Update local state immediately for better UX
				setRemainingCredits(newCreditCount);
				
				// Update credits in Xano
				await updateCreditsInXano(newCreditCount);
			} else if (freeRemaining > 0) {
				// Fallback to free credits if not authenticated
				setFreeUsed(freeUsed + 1);
			}
		} catch (e: any) {
			setError(e?.message || "Something went wrong");
			clearInterval(countdownTimer);
			setTimeoutActive(false);
		} finally {
			setIsSubmitting(false);
		}
	}, [canSubmit, freeRemaining, isAuthenticated, hasUnlimited, remainingCredits, webhookUrl, buildPayload, setFreeUsed, freeUsed, hasTriedToRun, setHasTriedToRun]);

	const handleAuth = useCallback(async () => {
		setAuthError(null);
		setAuthNotice(null);
		
		// Show terms modal for signup
		if (authMode === "signup") {
			setShowTermsModal(true);
			return;
		}
		
		setIsAuthLoading(true);
		try {
			const { token } = await xanoAuth(authMode, authEmail, authPassword, authName);
			console.log(`🔐 LOGIN SUCCESS: token=${!!token}`);
			setAuthToken(token);
			setAuthEmail(authEmail); // Persist email on login
			updateLastActive(); // Update last active on successful login
			// Credits will be fetched by useEffect after authentication
			setShowAuthModal(false);
		} catch (e: any) {
			setAuthError(e?.message || "Auth failed");
			// Show contact modal for authentication errors
			if (e?.message?.includes("Authentication failed") || e?.message?.includes("Auth failed")) {
				setShowContactModal(true);
			}
		} finally {
			setIsAuthLoading(false);
		}
	}, [authMode, authEmail, authPassword, authName, setAuthToken, setAuthEmail]);

	const handleTermsAgreement = useCallback(async () => {
		if (!agreedToTerms) return;
		
		setShowTermsModal(false);
		setIsAuthLoading(true);
		try {
			const { token } = await xanoAuth(authMode, authEmail, authPassword, authName);
			console.log(`🔐 SIGNUP SUCCESS: token received=${!!token}`);
			// Do NOT authenticate on signup; require explicit login afterwards
			setAuthNotice(null);
			setShowAuthModal(false);
			setAuthMode("login");
			setAuthPassword("");
			// Redirect user to dedicated login page with reminder flag
			if (typeof window !== "undefined") {
				window.location.href = "/login?signup=1";
			}
		} catch (e: any) {
			setAuthError(e?.message || "Auth failed");
			// Show contact modal for authentication errors
			if (e?.message?.includes("Authentication failed") || e?.message?.includes("Auth failed")) {
				setShowContactModal(true);
			}
		} finally {
			setIsAuthLoading(false);
		}
	}, [agreedToTerms, authMode, authEmail, authPassword, authName, setAuthToken]);

	useEffect(() => {
		console.log('useEffect: isAuthenticated', isAuthenticated, 'authEmail', authEmail);
		if (isAuthenticated && authEmail) {
			fetchCreditsFromXano();
		}
		// Optionally, you could refetch on every mount or login
	}, [isAuthenticated, authEmail]);

	// Fetch packages on component mount
	useEffect(() => {
		fetchPackagesFromXano();
	}, []);

	const [showChangePassModal, setShowChangePassModal] = useState(false);
	const [newPassword, setNewPassword] = useState("");
	const [isPassLoading, setIsPassLoading] = useState(false);
	const [passSuccess, setPassSuccess] = useState<string | null>(null);
	const [passError, setPassError] = useState<string | null>(null);

	// --- Password change handler ---
	const handleChangePassword = async () => {
	  setIsPassLoading(true);
	  setPassSuccess(null);
	  setPassError(null);
	  try {
		const response = await fetch(`${XANO_BASE_URL}${XANO_ME_PASS}`, {
		  method: "POST",
		  headers: { "Content-Type": "application/json" },
		  body: JSON.stringify({ email: authEmail, Password: newPassword })
		});
		if (!response.ok) {
		  throw new Error("Failed to update password.");
		}
		const data = await response.json();
		setPassSuccess(data ? JSON.stringify(data) : "Password updated successfully."); // you can format this nicer later
		setNewPassword("");
	  } catch (err: any) {
		setPassError(err?.message || "Failed to update password.");
	  } finally {
		setIsPassLoading(false);
	  }
	};

	if (!mounted) return null;

	return (
		<div className="min-h-screen bg-gray-50 py-10 px-4">
			<div className="mx-auto max-w-3xl">
				<div className="mb-6 flex items-center justify-between">
					<div className="flex items-center space-x-3">
						<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-600 to-purple-600 shadow-lg">
							<svg className="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
							</svg>
						</div>
						<div>
							<h1 className="text-2xl font-bold text-gray-800">Dr Curl</h1>
							<p className="text-sm text-gray-600">API Compatibility Checker</p>
						</div>
					</div>
					<div className="flex items-center gap-3 text-sm text-gray-600">
						<button
							onClick={() => {
								console.log('Download tutorial button clicked');
								downloadPptxTutorial();
							}}
							className="rounded-md bg-green-600 px-3 py-1.5 text-white shadow hover:bg-green-700"
						>
							📄 Download Tutorial
						</button>
						<button
							onClick={() => {
								console.log('Contact us button clicked');
								openEmailClient(ADMIN_SUPPORT_EMAIL, "Support Request", "Hello,\n\nI need assistance with the API Compatibility Checker.\n\nPlease describe your issue here...");
							}}
							className="rounded-md bg-gray-600 px-3 py-1.5 text-white shadow hover:bg-gray-700"
						>
							Contact us
						</button>
					{isAuthenticated ? (
							<span className="inline-flex items-center gap-2">
								{hasUnlimited ? (
									<span className="text-emerald-600 font-medium">Unlimited active</span>
								) : (
									<span>
										Credits: <strong>{remainingCredits ?? "?"}</strong>
									</span>
								)}
							</span>
					) : freeRemaining > 0 && hasTriedToRun ? (
						<span>
							<strong>{freeRemaining}</strong> free {freeRemaining === 1 ? "request" : "requests"} left
						</span>
					) : (
							<button
								onClick={() => setShowAuthModal(true)}
								className="rounded-md bg-indigo-600 px-3 py-1.5 text-white shadow hover:bg-indigo-700"
							>
								Sign in
							</button>
						)}
					{isAuthenticated && (
						<button
							onClick={() => {
								setShowChangePassModal(true);
								setPassSuccess(null);
								setPassError(null);
								setNewPassword("");
							}}
							className="rounded-md bg-purple-600 px-3 py-1.5 ml-2 text-white shadow hover:bg-purple-700"
						>
							Change Password
						</button>
					)}
					</div>
				</div>

				<div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
					<div className="mb-6 flex gap-2">
						{(["A", "B"] as CaseType[]).map((c) => (
							<button
								key={c}
								onClick={() => setCaseType(c)}
								className={classNames(
									"rounded-full px-4 py-1.5 text-sm font-medium",
									caseType === c ? "bg-indigo-600 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200"
								)}
							>
								{c === "A" && "Case A: Auto-Fix Your cURL"}
								{c === "B" && "Case B: Error Diagnosis/Generate cURL Request"}
							</button>
						))}
					</div>

					<div className="grid gap-4">
						<label className="block">
							<div className="mb-1 flex items-center gap-2">
								<span className="text-sm font-medium text-gray-700">Provider URL</span>
								<div className="relative">
									<button
										type="button"
										onMouseEnter={() => setShowProviderTooltip(true)}
										onMouseLeave={() => setShowProviderTooltip(false)}
										className="flex h-4 w-4 items-center justify-center rounded-full bg-gray-400 text-xs text-white hover:bg-gray-500"
									>
										?
									</button>
									{showProviderTooltip && (
										<div className="absolute bottom-full left-1/2 mb-2 w-64 -translate-x-1/2 transform rounded-lg bg-gray-900 px-3 py-2 text-xs text-white shadow-lg">
											This is the source endpoint - where your data comes from. For example, your backend API or database endpoint.
											<div className="absolute top-full left-1/2 h-0 w-0 -translate-x-1/2 transform border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
										</div>
									)}
								</div>
							</div>
							<input
								type="url"
								value={providerUrl}
								onChange={(e) => setProviderUrl(e.target.value)}
								placeholder="https://api.provider.com/openapi.json"
								className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
								required
							/>
						</label>

						<label className="block">
							<div className="mb-1 flex items-center gap-2">
								<span className="text-sm font-medium text-gray-700">Consumer URL</span>
								<div className="relative">
									<button
										type="button"
										onMouseEnter={() => setShowConsumerTooltip(true)}
										onMouseLeave={() => setShowConsumerTooltip(false)}
										className="flex h-4 w-4 items-center justify-center rounded-full bg-gray-400 text-xs text-white hover:bg-gray-500"
									>
										?
									</button>
									{showConsumerTooltip && (
										<div className="absolute bottom-full left-1/2 mb-2 w-64 -translate-x-1/2 transform rounded-lg bg-gray-900 px-3 py-2 text-xs text-white shadow-lg">
											This is the target endpoint - where the data is sent to or consumed. For example, your client API, webhook or integration endpoint. If you don't have any - fill here the provider URL as well 
											<div className="absolute top-full left-1/2 h-0 w-0 -translate-x-1/2 transform border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
										</div>
									)}
								</div>
							</div>
							<input
								type="url"
								value={consumerUrl}
								onChange={(e) => setConsumerUrl(e.target.value)}
								placeholder="https://api.consumer.com/openapi.json"
								className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
								required
							/>
						</label>

					{caseType === "C" && (
						<label className="block">
							<span className="mb-1 block text-sm font-medium text-gray-700">Task Explanation</span>
							<textarea
								value={taskExplanation}
								onChange={(e) => setTaskExplanation(e.target.value)}
								placeholder="Describe what you want the new cURL to accomplish including specifying Get/Post method"
								rows={3}
								className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
							/>
						</label>
					)}

						{caseType !== "C" && (
							<label className="block">
								<div className="mb-1 flex items-center gap-2">
									<span className={classNames("block font-medium text-gray-700", caseType === "B" ? "text-xs" : "text-sm")}>Your cURL</span>
									{(caseType === "A" || caseType === "B") && (
										<div className="relative">
											<button
												type="button"
												onMouseEnter={() => setShowCurlHelpTooltip(true)}
												onMouseLeave={() => setShowCurlHelpTooltip(false)}
												className="flex h-4 w-4 items-center justify-center rounded-full bg-gray-400 text-xs text-white hover:bg-gray-500"
											>
												?
											</button>
											{showCurlHelpTooltip && (
												<div className="absolute bottom-full left-1/2 mb-2 w-72 -translate-x-1/2 transform rounded-lg bg-gray-900 px-3 py-2 text-xs text-white shadow-lg z-10">
													Fill it only if you are getting errors in your own cURL command.
													<div className="absolute top-full left-1/2 h-0 w-0 -translate-x-1/2 transform border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
												</div>
											)}
										</div>
									)}
								</div>
								<textarea
									value={userCurl}
									onChange={(e) => setUserCurl(e.target.value)}
									placeholder={caseType === "B"
										? "Leave this field as a blank if you want to send a cURL generation request. Do not send your own real token in the command "
										: "curl -X POST https://api.provider.com/...Do not send your own real token in the command"}
									rows={caseType === "B" ? 3 : 4}
									className={classNames(
										"w-full rounded-lg border border-gray-300 bg-white text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500",
										caseType === "B" ? "px-3 py-1.5 text-sm" : "px-3 py-2"
									)}
									required={caseType !== "B"}
								/>
							</label>
						)}

						{caseType === "B" && (
							<label className="block">
								<div className="mb-1 flex items-center gap-2">
									<span className="block text-sm font-medium text-gray-700">
										Failure Reason / Generate cURL Request
									</span>
									<div className="relative">
										<button
											type="button"
											onMouseEnter={() => setShowFailureReasonHelpTooltip(true)}
											onMouseLeave={() => setShowFailureReasonHelpTooltip(false)}
											className="flex h-4 w-4 items-center justify-center rounded-full bg-gray-400 text-xs text-white hover:bg-gray-500"
										>
											?
										</button>
										{showFailureReasonHelpTooltip && (
											<div className="absolute bottom-full left-1/2 mb-2 w-80 -translate-x-1/2 transform rounded-lg bg-gray-900 px-3 py-2 text-xs text-white shadow-lg z-10">
												If your purpose is to generate a cURL command please describe clearly what you want the new cURL to accomplish.<br/>
												For example: Send POST request to Provider to create a new user with JSON body (name, email).
												<div className="absolute top-full left-1/2 h-0 w-0 -translate-x-1/2 transform border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
											</div>
										)}
									</div>
								</div>
								<input
									type="text"
									value={failureReason}
									onChange={(e) => setFailureReason(e.target.value)}
									placeholder="Describe the error you saw or what cURL you want to generate"
									className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
									required
								/>
							</label>
						)}

						{error && (
							<div className="rounded-md bg-red-50 p-3 text-sm text-red-700">{error}</div>
						)}

						<div className="flex flex-col gap-4 pt-2">
							<button
								onClick={handleSubmit}
								disabled={!canSubmit || isSubmitting}
								className={classNames(
								"inline-flex items-center justify-center rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white shadow hover:bg-indigo-700",
								caseType === "B" ? "text-sm md:text-base" : "text-base",
									(!canSubmit || isSubmitting) && "opacity-50 cursor-not-allowed"
								)}
							>
								{isSubmitting && (
									<span className="mr-2 inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-b-transparent" />
								)}
								Run Compatibility Check
							</button>

							{shouldGateOnAuthOrPayment && (
								<div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
									<div className="mb-2 font-medium">Trial exhausted</div>
									{!isAuthenticated ? (
										<button
											onClick={() => setShowAuthModal(true)}
											className="rounded-md bg-indigo-600 px-3 py-1.5 text-white shadow hover:bg-indigo-700"
										>
											Sign in to continue
										</button>
									) : hasUnlimited ? (
										<span>Unlimited active.</span>
									) : (
										<div className="flex flex-col gap-3">
											<span>Purchase credits to continue:</span>
											{!selectedPackage ? (
												<button
													onClick={() => setShowPackageModal(true)}
													className="rounded-md bg-indigo-600 px-4 py-2 text-white shadow hover:bg-indigo-700"
												>
													Choose Package
												</button>
											) : (
												<div className="space-y-3">
													<div className="rounded-lg border border-gray-200 bg-gray-50 p-3">
														<div className="font-medium text-gray-800">{selectedPackage.name}</div>
														<div className="text-sm text-gray-600">{selectedPackage.description}</div>
														<div className="text-sm text-gray-600">{selectedPackage.credits} credits</div>
														<div className="font-semibold text-indigo-600">${selectedPackage.price_usd}</div>
													</div>
													<div className="flex gap-2">
														<button
															onClick={() => setShowPackageModal(true)}
															className="rounded-md bg-gray-600 px-3 py-1.5 text-white shadow hover:bg-gray-700"
														>
															Change Package
														</button>
														<div className="flex-1">
															<div 
																ref={paypal.containerRef}
																className="pt-1" 
															/>
															{!paypal.isReady && (
																<div className="text-xs text-gray-500">PayPal loading...</div>
															)}
														</div>
													</div>
												</div>
											)}
										</div>
									)}
								</div>
							)}
						</div>
					</div>

					{timeoutActive && (
						<div className="mt-6 rounded-2xl bg-blue-50 p-6 shadow-sm ring-1 ring-blue-100">
							<div className="flex items-center justify-center">
								<div className="text-center">
									<div className="mb-2 inline-block h-8 w-8 animate-spin rounded-full border-4 border-blue-600 border-b-transparent"></div>
									<h3 className="text-lg font-semibold text-blue-800">Processing... please wait</h3>
									<p className="mt-1 text-sm text-blue-600">
										Estimated time remaining: <span className="font-mono font-bold">{timeRemaining}</span> seconds
									</p>
								</div>
							</div>
						</div>
					)}

					{result && (
						<div className="mt-6 rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
							<h2 className="mb-4 text-lg font-semibold text-gray-800">Result</h2>
							<div className="grid gap-3 text-sm text-gray-800">
							{caseType !== "A" && result.summary && (
									<div>
										<span className="font-medium">Summary:</span> {result.summary}
									</div>
								)}
							{caseType !== "A" && Array.isArray(result.issues) && result.issues.length > 0 && (
									<div>
										<div className="font-medium">Issues:</div>
										<ul className="ml-5 list-disc">
											{result.issues.map((x, i) => (
												<li key={i}>{x}</li>
											))}
										</ul>
									</div>
								)}
								{caseType !== "A" && result.fixed_curl && (
									<div>
										<div className="font-medium">Fixed cURL:</div>
										<pre className="mt-1 overflow-auto rounded-lg bg-gray-900 p-3 text-gray-100"><code>{result.fixed_curl}</code></pre>
									</div>
								)}
							{caseType !== "A" && result.diagnosis && (
									<div>
										<span className="font-medium">Diagnosis:</span> {result.diagnosis}
									</div>
								)}
							{caseType !== "A" && result.recommendation && (
									<div>
										<span className="font-medium">Recommendation:</span> {result.recommendation}
									</div>
								)}
							{caseType !== "A" && Array.isArray(result.headers_to_change) && result.headers_to_change.length > 0 && (
									<div>
										<div className="font-medium">Headers to change:</div>
										<ul className="ml-5 list-disc">
											{result.headers_to_change.map((x, i) => (
												<li key={i}>{x}</li>
											))}
										</ul>
									</div>
								)}
							{caseType !== "A" && Array.isArray(result.body_mapping) && result.body_mapping.length > 0 && (
									<div>
										<div className="font-medium">Body mapping:</div>
										<ul className="ml-5 list-disc">
											{result.body_mapping.map((x, i) => (
												<li key={i}>{x}</li>
											))}
										</ul>
									</div>
								)}
							{caseType !== "A" && (
								<div className="mt-2 text-sm text-gray-700">Missing info: {result.missing_info ? "Yes" : "No"}</div>
							)}

								<div className="mt-4 flex flex-wrap items-center gap-2">
								<button
									onClick={() => displayedJson && copyToClipboard(formatJson(displayedJson))}
										className="rounded-md bg-gray-800 px-3 py-1.5 text-sm text-white shadow hover:bg-gray-900"
									>
										Copy JSON
									</button>
									<button
									onClick={() => displayedJson && downloadTextAsFile("compatibility_result.json", formatJson(displayedJson))}
										className="rounded-md bg-white px-3 py-1.5 text-sm text-gray-800 ring-1 ring-gray-300 hover:bg-gray-50"
									>
										Download JSON
									</button>
									<button
										onClick={async () => {
											const link = generateShareLinkPlaceholder();
											await copyToClipboard(link);
											alert(`Share link copied: ${link}`);
										}}
										className="rounded-md bg-white px-3 py-1.5 text-sm text-gray-800 ring-1 ring-gray-300 hover:bg-gray-50"
									>
										Share
									</button>
								</div>

								<div className="mt-4">
									<pre className="max-h-96 overflow-auto rounded-lg bg-gray-900 p-4 text-gray-100"><code>{formatJson(displayedJson)}</code></pre>
								</div>
							</div>
						</div>
					)}
				</div>

				{showAuthModal && (
					<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
						<div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-lg">
							<div className="mb-4 flex items-center justify-between">
								<div className="flex items-center space-x-3">
									<div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-600 to-purple-600 shadow-md">
										<svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
										</svg>
									</div>
									<h3 className="text-lg font-semibold text-gray-800">{authMode === "login" ? "Sign in" : "Create account"}</h3>
								</div>
								<button onClick={() => setShowAuthModal(false)} className="rounded-md p-1 text-gray-500 hover:bg-gray-100">✕</button>
							</div>
							<div className="grid gap-3">
								{authMode === "signup" && (
									<label className="block">
										<span className="mb-1 block text-sm font-medium text-gray-700">Name</span>
										<input
											type="text"
											value={authName}
											onChange={(e) => setAuthName(e.target.value)}
											placeholder="Enter your full name"
											className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
											required={authMode === "signup"}
										/>
									</label>
								)}
								<label className="block">
									<span className="mb-1 block text-sm font-medium text-gray-700">Email</span>
									<input
										type="email"
										value={authEmail}
										onChange={(e) => setAuthEmail(e.target.value)}
										className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
										required
									/>
								</label>
								<label className="block">
									<span className="mb-1 block text-sm font-medium text-gray-700">Password</span>
									<input
										type="password"
										value={authPassword}
										onChange={(e) => setAuthPassword(e.target.value)}
										className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
										required
									/>
								</label>
				{authError && <div className="rounded-md bg-red-50 p-3 text-sm text-red-700">{authError}</div>}
				{authNotice && <div className="rounded-md bg-green-50 p-3 text-sm text-green-700">{authNotice}</div>}
								<button
									onClick={handleAuth}
									disabled={isAuthLoading || !authEmail || !authPassword || (authMode === "signup" && !authName)}
									className={classNames(
										"mt-1 inline-flex items-center justify-center rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white shadow hover:bg-indigo-700",
										(isAuthLoading || !authEmail || !authPassword || (authMode === "signup" && !authName)) && "opacity-50 cursor-not-allowed"
									)}
								>
									{isAuthLoading && (
										<span className="mr-2 inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-b-transparent" />
									)}
									{authMode === "login" ? "Sign in" : "Sign up"}
								</button>
								<div className="text-center text-sm text-gray-600">
									{authMode === "login" ? (
										<button onClick={() => {
											setAuthMode("signup");
											setAuthName("");
											setAuthEmail("");
											setAuthPassword("");
											setAuthError(null);
										}} className="mt-2 text-indigo-600 hover:underline">Need an account? Sign up</button>
									) : (
										<button onClick={() => {
											setAuthMode("login");
											setAuthName("");
											setAuthEmail("");
											setAuthPassword("");
											setAuthError(null);
										}} className="mt-2 text-indigo-600 hover:underline">Have an account? Sign in</button>
									)}
								</div>
							</div>
						</div>
					</div>
				)}

				{showTermsModal && (
					<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
						<div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-lg">
							<div className="mb-4 flex items-center justify-between">
								<div className="flex items-center space-x-3">
									<div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-600 to-purple-600 shadow-md">
										<svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
										</svg>
									</div>
									<h3 className="text-lg font-semibold text-gray-800">Terms & Conditions</h3>
								</div>
								<button 
									onClick={() => {
										setShowTermsModal(false);
										setAgreedToTerms(false);
									}} 
									className="rounded-md p-1 text-gray-500 hover:bg-gray-100"
								>
									✕
								</button>
							</div>
							
							<div className="mb-6 max-h-96 overflow-y-auto text-sm text-gray-700">
								<h4 className="mb-3 font-semibold text-gray-800">Marketing Communications Agreement</h4>
								<p className="mb-3">
									By creating an account, you agree to receive promotional communications from our website, including:
								</p>
								<ul className="mb-4 ml-4 list-disc space-y-1">
									<li>Email newsletters with product updates and features</li>
									<li>Special offers and promotional discounts</li>
									<li>New service announcements and improvements</li>
									<li>API usage tips and best practices</li>
									<li>Industry news and insights</li>
								</ul>
								<p className="mb-3">
									You can unsubscribe from these communications at any time by clicking the unsubscribe link in any email we send you.
								</p>
								<p className="text-xs text-gray-500">
									We respect your privacy and will never share your information with third parties without your consent.
								</p>
							</div>
							
							<div className="mb-4">
								<label className="flex items-start space-x-3">
									<input
										type="checkbox"
										checked={agreedToTerms}
										onChange={(e) => setAgreedToTerms(e.target.checked)}
										className="mt-1 h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
									/>
									<span className="text-sm text-gray-700">
										I agree to receive promotional communications from this website and have read the terms above.
									</span>
								</label>
							</div>
							
							<div className="flex gap-3">
								<button
									onClick={() => {
										setShowTermsModal(false);
										setAgreedToTerms(false);
									}}
									className="flex-1 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow hover:bg-gray-50"
								>
									Cancel
								</button>
								<button
									onClick={handleTermsAgreement}
									disabled={!agreedToTerms || isAuthLoading}
									className={classNames(
										"flex-1 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700",
										(!agreedToTerms || isAuthLoading) && "opacity-50 cursor-not-allowed"
									)}
								>
									{isAuthLoading && (
										<span className="mr-2 inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-b-transparent" />
									)}
									Agree & Continue
								</button>
							</div>
						</div>
					</div>
				)}

				{showContactModal && (
					<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
						<div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-lg">
							<div className="mb-4 flex items-center justify-between">
								<div className="flex items-center space-x-3">
									<div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-red-600 to-orange-600 shadow-md">
										<svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
										</svg>
									</div>
									<h3 className="text-lg font-semibold text-gray-800">Authentication Error</h3>
								</div>
								<button 
									onClick={() => setShowContactModal(false)} 
									className="rounded-md p-1 text-gray-500 hover:bg-gray-100"
								>
									✕
								</button>
							</div>
							
							<div className="mb-6 text-sm text-gray-700">
								<p className="mb-3">
									We're sorry, but there was an issue with your authentication. This could be due to:
								</p>
								<ul className="mb-4 ml-4 list-disc space-y-1">
									<li>Incorrect email or password</li>
									<li>Account not yet activated</li>
									<li>Server connectivity issues</li>
									<li>Account suspended or disabled</li>
								</ul>
								<p className="mb-3">
									If you continue to experience issues, please contact our support team for assistance.
								</p>
							</div>
							
							<div className="flex gap-3">
								<button
									onClick={() => setShowContactModal(false)}
									className="flex-1 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow hover:bg-gray-50"
								>
									Try Again
								</button>
								<button
									onClick={() => {
										setShowContactModal(false);
										openEmailClient(ADMIN_SUPPORT_EMAIL, "Authentication Support Request", "Hello,\n\nI'm experiencing authentication issues with the API Compatibility Checker.\n\nError details:\n- Authentication failed\n- Unable to sign in\n\nPlease help me resolve this issue.\n\nThank you!");
									}}
									className="flex-1 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-red-700"
								>
									Contact Support
								</button>
							</div>
						</div>
					</div>
				)}

				{showPackageModal && (
					<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
						<div className="w-full max-w-2xl rounded-2xl bg-white p-6 shadow-lg">
							<div className="mb-4 flex items-center justify-between">
								<div className="flex items-center space-x-3">
									<div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-600 to-purple-600 shadow-md">
										<svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1" />
										</svg>
									</div>
									<h3 className="text-lg font-semibold text-gray-800">Choose Your Package</h3>
								</div>
								<button 
									onClick={() => setShowPackageModal(false)} 
									className="rounded-md p-1 text-gray-500 hover:bg-gray-100"
								>
									✕
								</button>
							</div>
							
							{isLoadingPackages ? (
								<div className="flex items-center justify-center py-8">
									<div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-indigo-600 border-b-transparent"></div>
									<span className="ml-3 text-gray-600">Loading packages...</span>
								</div>
							) : packages.length === 0 ? (
								<div className="text-center py-8 text-gray-600">
									No packages available at the moment.
								</div>
							) : (
								<div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
									{packages.map((pkg) => (
										<div
											key={pkg.name}
											onClick={() => {
												setSelectedPackage(pkg);
												setShowPackageModal(false);
											}}
											className={`cursor-pointer rounded-lg border p-4 transition-all hover:shadow-md ${
												selectedPackage?.name === pkg.name
													? 'border-indigo-500 bg-indigo-50'
													: 'border-gray-200 bg-white hover:border-gray-300'
											}`}
										>
											<div className="mb-2">
												<h4 className="font-semibold text-gray-800">{pkg.name}</h4>
												<p className="text-sm text-gray-600">{pkg.description}</p>
											</div>
											<div className="mb-3">
												<div className="text-lg font-bold text-indigo-600">${pkg.price_usd}</div>
												<div className="text-sm text-gray-500">{pkg.credits} credits</div>
											</div>
											<button
												className={`w-full rounded-md px-3 py-2 text-sm font-medium ${
													selectedPackage?.name === pkg.name
														? 'bg-indigo-600 text-white'
														: 'bg-gray-100 text-gray-700 hover:bg-gray-200'
												}`}
											>
												{selectedPackage?.name === pkg.name ? 'Selected' : 'Select'}
											</button>
										</div>
									))}
								</div>
							)}
							
							<div className="mt-6 flex justify-end">
								<button
									onClick={() => setShowPackageModal(false)}
									className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow hover:bg-gray-50"
								>
									Cancel
								</button>
							</div>
						</div>
					</div>
				)}

				{/* Footer with Policy Links */}
				<div className="mt-8 text-center">
					<button
						onClick={() => setShowPolicyModal(true)}
						className="text-sm text-gray-500 hover:text-gray-700 underline"
					>
						Privacy Policy / Terms & Conditions / Accessibility Statement / Refund Policy
					</button>
				</div>
			</div>

			{/* Policy Modal */}
			{showPolicyModal && (
				<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
					<div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-lg">
						<div className="mb-4 flex items-center justify-between">
							<div className="flex items-center space-x-3">
								<div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-600 to-purple-600">
									<svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
									</svg>
								</div>
								<h3 className="text-lg font-semibold text-gray-800">Legal Documents</h3>
							</div>
							<button 
								onClick={() => setShowPolicyModal(false)} 
								className="rounded-md p-1 text-gray-500 hover:bg-gray-100"
							>
								✕
							</button>
						</div>
						
						<div className="mb-6 text-sm text-gray-700">
							<p className="mb-3">
								To view our Privacy Policy, Terms & Conditions, Accessibility Statement, and Refund Policy, 
								please visit our main website and scroll to the bottom of the page.
							</p>
							<p className="mb-4">
								The documents are located at the bottom of the page after clicking the link below.
							</p>
						</div>
						
						<div className="flex gap-3">
							<button
								onClick={() => {
									setShowPolicyModal(false);
									window.open('https://www.heal-api.net/', '_blank');
								}}
								className="flex-1 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700"
							>
								Visit Website
							</button>
							<button
								onClick={() => setShowPolicyModal(false)}
								className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow hover:bg-gray-50"
							>
								Cancel
							</button>
						</div>
					</div>
				</div>
			)}
			{showChangePassModal && (
				<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
					<div className="w-full max-w-sm rounded-2xl bg-white p-6 shadow-lg">
						<div className="mb-4 flex items-center justify-between">
							<h3 className="text-lg font-semibold text-gray-800">Change Password</h3>
							<button
								onClick={() => setShowChangePassModal(false)}
								className="rounded-md p-1 text-gray-500 hover:bg-gray-100"
							>✕</button>
						</div>
						<label className="block mb-4">
							<span className="block text-sm font-medium text-gray-700 mb-1">New Password</span>
							<input
								type="password"
								value={newPassword}
								onChange={(e) => setNewPassword(e.target.value)}
								className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
								autoFocus
							/>
						</label>
						{passError && <div className="mb-2 text-sm text-red-600">{passError}</div>}
						{passSuccess && <div className="mb-2 text-sm text-green-600">{passSuccess}</div>}
						<div className="flex gap-2 mt-4">
							<button
								onClick={handleChangePassword}
								disabled={isPassLoading || !newPassword}
								className={`flex-1 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700 ${(!newPassword || isPassLoading) ? 'opacity-50 cursor-not-allowed' : ''}`}
							>
								{isPassLoading ? 'Updating...' : 'Submit'}
							</button>
							<button
								onClick={() => setShowChangePassModal(false)}
								className="flex-1 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow hover:bg-gray-50"
							>
								Cancel
							</button>
						</div>
					</div>
				</div>
			)}
		</div>
	);
}



