<script lang="ts">
	import { goto } from '$app/navigation';
	import { forgotPassword } from '$lib/apis/auths';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import { WEBUI_NAME } from '$lib/stores';
	import { toast } from 'svelte-sonner';

	const recoveryHighlights = [
		'通过注册邮箱接收安全重置链接',
		'重置过程不会暴露当前密码',
		'完成后可继续使用官方 API 满血模型'
	];

	let email = '';
	let loading = false;

	const handleSubmit = async () => {
		if (!email.trim()) {
			toast.error('请输入邮箱地址');
			return;
		}

		loading = true;
		try {
			const res = await forgotPassword(email.trim());
			toast.success(res.message || '如果该邮箱地址已注册，您将收到密码重置邮件');
			email = '';
		} catch (error) {
			toast.error(typeof error === 'string' ? error : '发送失败，请稍后重试');
		} finally {
			loading = false;
		}
	};
</script>

<svelte:head>
	<title>忘记密码 - {$WEBUI_NAME}</title>
</svelte:head>

<div class="auth-recovery-page fixed inset-0 overflow-y-auto text-white">
	<div class="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col px-5 py-10 font-primary sm:px-8 lg:px-10">
		<div class="my-auto grid w-full items-center gap-10 py-10 lg:grid-cols-[1.05fr_0.95fr] lg:gap-14">
			<section class="text-left">
				<div class="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-100 shadow-lg shadow-cyan-950/20 backdrop-blur">
					Account Recovery
				</div>
				<h1 class="mt-7 max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
					安全找回账户，继续使用满血模型能力
				</h1>
				<p class="mt-5 max-w-2xl text-base leading-8 text-slate-200 sm:text-lg">
					输入注册邮箱后，我们会发送一封密码重置邮件。完成验证后即可回到工作台，继续使用 GPT、Gemini、Claude 等官方 API 模型。
				</p>

				<div class="mt-8 grid gap-3">
					{#each recoveryHighlights as item}
						<div class="flex items-center gap-3 rounded-2xl border border-white/15 bg-white/[0.08] px-4 py-3 text-sm text-slate-100 backdrop-blur-xl">
							<span class="flex size-7 shrink-0 items-center justify-center rounded-full bg-cyan-300/15 text-cyan-100 ring-1 ring-cyan-200/20">
								<svg
									xmlns="http://www.w3.org/2000/svg"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
									stroke-width="1.8"
									class="size-4"
									aria-hidden="true"
								>
									<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
								</svg>
							</span>
							<span>{item}</span>
						</div>
					{/each}
				</div>
			</section>

			<section class="w-full">
				<div class="mx-auto w-full max-w-md rounded-[2rem] border border-white/20 bg-white/95 p-6 text-slate-950 shadow-2xl shadow-blue-950/30 backdrop-blur-2xl dark:border-white/10 dark:bg-slate-950/85 dark:text-white sm:p-8">
					<button
						class="inline-flex items-center text-sm font-semibold text-slate-500 transition hover:text-slate-950 dark:text-slate-400 dark:hover:text-white"
						type="button"
						on:click={() => goto('/auth')}
					>
						<svg class="mr-2 size-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
						</svg>
						返回登录
					</button>

					<div class="mt-8">
						<h2 class="text-2xl font-semibold tracking-tight text-slate-950 dark:text-white">忘记密码</h2>
						<p class="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">
							输入您的邮箱地址，我们将发送密码重置链接给您。
						</p>
					</div>

					<form class="mt-8 space-y-6" on:submit|preventDefault={handleSubmit}>
						<div>
							<label for="email" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
								邮箱地址
							</label>
							<input
								id="email"
								name="email"
								type="email"
								autocomplete="email"
								required
								bind:value={email}
								disabled={loading}
								class="w-full rounded-2xl border border-slate-200 bg-white/80 px-4 py-3 text-sm text-slate-950 outline-hidden transition placeholder:text-slate-400 focus:border-cyan-400 focus:ring-4 focus:ring-cyan-400/10 disabled:cursor-not-allowed disabled:opacity-60 dark:border-white/10 dark:bg-white/5 dark:text-white dark:placeholder:text-slate-500"
								placeholder="请输入您的邮箱地址"
							/>
						</div>

						<button
							type="submit"
							disabled={loading}
							class="flex w-full items-center justify-center rounded-2xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-slate-950/20 transition hover:-translate-y-0.5 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-cyan-300 dark:text-slate-950 dark:shadow-cyan-950/30 dark:hover:bg-cyan-200"
						>
							{#if loading}
								<Spinner className="mr-2 size-4" />
								发送中...
							{:else}
								发送重置邮件
							{/if}
						</button>
					</form>

					<div class="mt-6">
						<div class="relative">
							<div class="absolute inset-0 flex items-center">
								<div class="w-full border-t border-slate-200 dark:border-white/10"></div>
							</div>
							<div class="relative flex justify-center text-sm">
								<span class="bg-white px-3 text-slate-500 dark:bg-slate-950 dark:text-slate-400">或</span>
							</div>
						</div>

						<button
							type="button"
							class="mt-6 flex w-full justify-center rounded-2xl border border-slate-200 bg-white/70 px-4 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 dark:border-white/10 dark:bg-white/5 dark:text-slate-200 dark:hover:bg-white/10"
							on:click={() => goto('/auth')}
						>
							返回登录页面
						</button>
					</div>
				</div>
			</section>
		</div>
	</div>
</div>

<style>
	.auth-recovery-page {
		background:
			radial-gradient(circle at top left, rgba(34, 211, 238, 0.28), transparent 32rem),
			radial-gradient(circle at 78% 18%, rgba(59, 130, 246, 0.24), transparent 30rem),
			linear-gradient(135deg, #020617 0%, #0f172a 44%, #111827 100%);
	}

	.auth-recovery-page::before {
		position: fixed;
		inset: 0;
		pointer-events: none;
		content: '';
		background-image:
			linear-gradient(rgba(255, 255, 255, 0.05) 1px, transparent 1px),
			linear-gradient(90deg, rgba(255, 255, 255, 0.05) 1px, transparent 1px);
		background-size: 72px 72px;
		mask-image: linear-gradient(to bottom, rgba(0, 0, 0, 0.9), transparent 80%);
	}
</style>
