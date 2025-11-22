"use client";

import Link from "next/link";
import type { Route } from "next";

export default function WelcomePage() {
	return (
		<main className="min-h-screen bg-white text-gray-900">
			<section className="relative overflow-hidden">
				<div className="absolute inset-0 bg-gradient-to-br from-indigo-50 via-white to-blue-50" />
				<div className="relative mx-auto max-w-6xl px-6 pt-20 pb-16 md:pt-28 md:pb-24">
					<div className="md:grid md:grid-cols-2 md:gap-12 items-center">
						<div className="max-w-3xl">
							<h1 className="text-4xl font-extrabold tracking-tight text-gray-900 md:text-6xl">
								Fix your API in minutes. Not hours.
							</h1>
							<p className="mt-4 text-lg leading-7 text-gray-700 md:text-xl md:leading-8">
								Stop wasting time debugging cURL errors, missing headers, and no-code integration mismatches.
								Heal-API analyzes your request, compares it to the API rules — and shows exactly what to fix.
							</p>
							<div className="mt-5 inline-flex items-center rounded-full bg-blue-50 px-4 py-2 text-sm text-blue-800 ring-1 ring-inset ring-blue-200">
								⭐ You get 3 free API diagnostic runs — no credit card required.
							</div>
							<div className="mt-8 flex flex-col items-start gap-3 sm:flex-row">
								<Link
									href={"/" as Route}
									className="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-5 py-3 text-base font-medium text-white shadow hover:bg-indigo-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
								>
									▶ Start Free
								</Link>
								<Link
									href={"/" as Route}
									className="inline-flex items-center justify-center rounded-lg border border-gray-300 px-5 py-3 text-base font-medium text-gray-800 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
								>
									Login
								</Link>
							</div>
						</div>
						<div className="mt-10 md:mt-0 flex justify-center md:justify-end">
							<img
								src="/dr-curl-2.jpg"
								alt="DR CURL"
								className="h-56 w-56 md:h-72 md:w-72 rounded-xl ring-1 ring-blue-200/50 shadow-sm object-contain bg-white/40"
							/>
						</div>
					</div>
				</div>
			</section>

			<section className="border-t border-gray-100 bg-white">
				<div className="mx-auto max-w-6xl px-6 py-14 md:py-16">
					<div className="grid gap-8 md:grid-cols-3">
						<div className="rounded-2xl border border-gray-100 p-6 shadow-sm">
							<div className="mb-3 text-2xl">🔹 1. Detect cURL mismatches automatically</div>
							<p className="text-gray-700">
								Wrong method? Wrong header? Wrong body format? Heal-API highlights the exact mismatch between what you sent and what the server expects.
							</p>
						</div>
						<div className="rounded-2xl border border-gray-100 p-6 shadow-sm">
							<div className="mb-3 text-2xl">🔹 2. Fix no-code platform errors (Xano, Zapier, WeWeb, Bubble)</div>
							<p className="text-gray-700">
								Your tool sends one thing — the backend expects another. We compare both sides and show the corrected request.
							</p>
						</div>
						<div className="rounded-2xl border border-gray-100 p-6 shadow-sm">
							<div className="mb-3 text-2xl">🔹 3. See the real root-cause of 400/401/404/422</div>
							<p className="text-gray-700">
								Stop guessing. Heal-API tells you why your call failed — and how to fix it in under 30 seconds.
							</p>
						</div>
					</div>
				</div>
			</section>

			<section className="bg-gray-50">
				<div className="mx-auto max-w-6xl px-6 py-14 md:py-16">
					<h2 className="text-2xl font-bold text-gray-900 md:text-3xl">How it works</h2>
					<div className="mt-8 grid gap-6 md:grid-cols-3">
						<div className="rounded-2xl bg-white p-6 ring-1 ring-gray-100 shadow-sm">
							<h3 className="text-lg font-semibold text-gray-900">Step 1 — Paste your broken API request</h3>
							<p className="mt-2 text-gray-700">
								cURL, Xano logs, Zapier request, WeWeb action, JavaScript fetch — anything.
							</p>
						</div>
						<div className="rounded-2xl bg-white p-6 ring-1 ring-gray-100 shadow-sm">
							<h3 className="text-lg font-semibold text-gray-900">Step 2 — Heal-API analyzes the call</h3>
							<p className="mt-2 text-gray-700">
								We detect structure issues, missing headers, body mismatches, auth problems, and compare to docs.
							</p>
						</div>
						<div className="rounded-2xl bg-white p-6 ring-1 ring-gray-100 shadow-sm">
							<h3 className="text-lg font-semibold text-gray-900">Step 3 — Get the fixed version instantly</h3>
							<p className="mt-2 text-gray-700">
								See the corrected request with exact changes needed.
							</p>
						</div>
					</div>
					<div className="mt-8">
						<Link
							href={"/" as Route}
							className="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-5 py-3 text-base font-medium text-white shadow hover:bg-indigo-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
						>
							▶ Start Free (3 runs)
						</Link>
					</div>
				</div>
			</section>

			<section className="bg-white">
				<div className="mx-auto max-w-6xl px-6 py-14 md:py-16">
					<h2 className="text-2xl font-bold text-gray-900 md:text-3xl">
						Developers use Heal-API to save hours every week
					</h2>
					<div className="mt-4 space-y-2 text-gray-700">
						<p>Stop manually testing request variations.</p>
						<p>Stop chasing unknown errors.</p>
						<p>Start shipping faster.</p>
					</div>
				</div>
			</section>

			<section className="border-t border-gray-100 bg-gray-50">
				<div className="mx-auto max-w-6xl px-6 py-14 md:py-16">
					<div className="max-w-2xl">
						<h2 className="text-3xl font-extrabold text-gray-900">Ready to fix your API?</h2>
						<div className="mt-6 flex flex-col items-start gap-3 sm:flex-row">
							<Link
								href={"/" as Route}
								className="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-5 py-3 text-base font-medium text-white shadow hover:bg-indigo-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
							>
								▶ Start Free
							</Link>
							<div className="text-sm text-gray-600">
								No credit card. No commitment. <br className="hidden sm:block" /> Just instant clarity for your API.
							</div>
						</div>
					</div>
				</div>
			</section>
		</main>
	);
}


