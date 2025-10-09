"use client";
export const dynamic = "force-dynamic";

import React, { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

const XANO_BASE_URL = process.env.NEXT_PUBLIC_XANO_BASE_URL || "https://x8ki-letl-twmt.n7.xano.io/api:oNjZ-H43";
const XANO_LOGIN_PATH = "/auth/login";
const LS_AUTH_TOKEN_KEY = "api-compat-xanoToken"; // Must match LS_KEYS.authToken

function LoginPageContent() {
	const router = useRouter();
	const params = useSearchParams();
	const fromSignup = params.get("signup") === "1";

	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);

	useEffect(() => {
		if (fromSignup) {
			setNotice("Account created. Please verify your email, then sign in.");
		}
	}, [fromSignup]);

	const canSubmit = useMemo(() => {
		return email.trim().length > 0 && password.trim().length > 0;
	}, [email, password]);

	const handleLogin = useCallback(async () => {
		setError(null);
		setIsLoading(true);
		try {
			const endpoint = `${XANO_BASE_URL}${XANO_LOGIN_PATH}`;
			const res = await fetch(endpoint, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email, password })
			});
			if (!res.ok) {
				throw new Error("Authentication failed - check your credentials");
			}
			const data = (await res.json()) as { authToken?: string; token?: string };
			const token = (data as any).authToken || (data as any).token;
			if (!token) {
				throw new Error("No token returned by server");
			}
			// Store token where the app expects it
			localStorage.setItem(LS_AUTH_TOKEN_KEY, token);
			// Redirect back to home (tool will read token and fetch credits)
			router.push("/");
		} catch (e: any) {
			setError(e?.message || "Login failed");
		} finally {
			setIsLoading(false);
		}
	}, [email, password, router]);

	return (
		<div className="min-h-screen bg-gray-50 py-10 px-4">
			<div className="mx-auto w-full max-w-md rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
				<div className="mb-4 flex items-center justify-between">
					<div className="flex items-center space-x-3">
						<div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-600 to-purple-600 shadow-md">
							<svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
							</svg>
						</div>
						<h1 className="text-lg font-semibold text-gray-800">Sign in</h1>
					</div>
				</div>

				{/* Verification reminder */}
				<div className="mb-4 rounded-md bg-blue-50 p-3 text-sm text-blue-800">
					Please verify your email address before signing in.
				</div>
				{notice && (
					<div className="mb-3 rounded-md bg-green-50 p-3 text-sm text-green-700">{notice}</div>
				)}
				{error && (
					<div className="mb-3 rounded-md bg-red-50 p-3 text-sm text-red-700">{error}</div>
				)}

				<label className="mb-2 block">
					<span className="mb-1 block text-sm font-medium text-gray-700">Email</span>
					<input
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
						required
					/>
				</label>
				<label className="mb-4 block">
					<span className="mb-1 block text-sm font-medium text-gray-700">Password</span>
					<input
						type="password"
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
						required
					/>
				</label>

				<button
					onClick={handleLogin}
					disabled={!canSubmit || isLoading}
					className={`inline-flex w-full items-center justify-center rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white shadow hover:bg-indigo-700 ${(!canSubmit || isLoading) ? "opacity-50 cursor-not-allowed" : ""}`}
				>
					{isLoading && (
						<span className="mr-2 inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-b-transparent" />
					)}
					Sign in
				</button>

				<div className="mt-4 text-center text-sm text-gray-600">
					<button
						onClick={() => router.push("/")}
						className="text-indigo-600 hover:underline"
					>
						Back to app
					</button>
				</div>
			</div>
		</div>
	);
}

export default function LoginPage() {
	return (
		<Suspense fallback={<div>Loading...</div>}>
			<LoginPageContent />
		</Suspense>
	);
}





