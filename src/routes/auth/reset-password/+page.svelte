<script lang="ts">
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { resetPassword } from '$lib/apis/auths';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import { WEBUI_NAME } from '$lib/stores';
	import { toast } from 'svelte-sonner';
	import { onMount } from 'svelte';

	const resetHighlights = [
		'重置链接仅用于当前账户验证',
		'强密码规则帮助保护模型额度与团队数据',
		'完成后自动返回登录入口'
	];

	let token = '';
	let newPassword = '';
	let confirmPassword = '';
	let loading = false;
	let showPassword = false;

	onMount(() => {
		token = $page.url.searchParams.get('token') || '';
		if (!token) {
			toast.error('重置链接无效');
			goto('/auth');
		}
	});

	const handleSubmit = async () => {
		if (!newPassword.trim()) {
			toast.error('请输入新密码');
			return;
		}

		if (newPassword !== confirmPassword) {
			toast.error('两次输入的密码不一致');
			return;
		}

		if (newPassword.length < 8) {
			toast.error('密码长度至少为8位');
			return;
		}

		loading = true;
		try {
			const res = await resetPassword(token, newPassword);
			toast.success(res.message || '密码重置成功');
			goto('/auth');
		} catch (error) {
			toast.error(typeof error === 'string' ? error : '重置失败，请重试');
		} finally {
			loading = false;
		}
	};

	const validatePassword = (password: string) => {
		const hasUpperCase = /[A-Z]/.test(password);
		const hasLowerCase = /[a-z]/.test(password);
		const hasNumbers = /\d/.test(password);
		const hasNonalphas = /\W/.test(password);
		
		return {
			length: password.length >= 8,
			uppercase: hasUpperCase,
			lowercase: hasLowerCase,
			number: hasNumbers,
			special: hasNonalphas
		};
	};

	$: passwordValidation = validatePassword(newPassword);
	$: isValidPassword = Object.values(passwordValidation).every(v => v);
</script>

<svelte:head>
	<title>重置密码 - {$WEBUI_NAME}</title>
</svelte:head>

<div class="auth-reset-page fixed inset-0 overflow-y-auto text-white">
	<div class="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col px-5 py-10 font-primary sm:px-8 lg:px-10">
		<div class="my-auto grid w-full items-center gap-10 py-10 lg:grid-cols-[1.05fr_0.95fr] lg:gap-14">
			<section class="text-left">
				<div class="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-100 shadow-lg shadow-cyan-950/20 backdrop-blur">
					Secure Reset
				</div>
				<h1 class="mt-7 max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
					设置强密码，保护你的模型访问权限
				</h1>
				<p class="mt-5 max-w-2xl text-base leading-8 text-slate-200 sm:text-lg">
					新的密码会用于保护账户、团队数据和官方 API 模型额度。请使用足够复杂的密码，完成后即可返回登录页面。
				</p>

				<div class="mt-8 grid gap-3">
					{#each resetHighlights as item}
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
						<h2 class="text-2xl font-semibold tracking-tight text-slate-950 dark:text-white">重置密码</h2>
						<p class="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">
							请输入一个满足规则的新密码。
						</p>
					</div>

					<form class="mt-8 space-y-5" on:submit|preventDefault={handleSubmit}>
						<div>
							<label for="new-password" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
								新密码
							</label>
							<div class="relative">
								<input
									id="new-password"
									name="new-password"
									type={showPassword ? 'text' : 'password'}
									autocomplete="new-password"
									required
									bind:value={newPassword}
									disabled={loading}
									class="w-full rounded-2xl border border-slate-200 bg-white/80 px-4 py-3 pr-12 text-sm text-slate-950 outline-hidden transition placeholder:text-slate-400 focus:border-cyan-400 focus:ring-4 focus:ring-cyan-400/10 disabled:cursor-not-allowed disabled:opacity-60 dark:border-white/10 dark:bg-white/5 dark:text-white dark:placeholder:text-slate-500"
									placeholder="请输入新密码"
								/>
								<button
									type="button"
									class="absolute inset-y-0 right-0 flex items-center pr-4 text-slate-400 transition hover:text-slate-700 dark:hover:text-white"
									on:click={() => (showPassword = !showPassword)}
									aria-label={showPassword ? '隐藏密码' : '显示密码'}
								>
									{#if showPassword}
										<svg class="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
										</svg>
									{:else}
										<svg class="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
										</svg>
									{/if}
								</button>
							</div>

							{#if newPassword}
								<div class="mt-3 grid gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/[0.04]">
									<div class="flex items-center text-xs {passwordValidation.length ? 'text-emerald-600 dark:text-emerald-300' : 'text-red-600 dark:text-red-300'}">
										<span class="mr-2 size-1.5 rounded-full {passwordValidation.length ? 'bg-emerald-500' : 'bg-red-500'}"></span>
										至少8位字符
									</div>
									<div class="flex items-center text-xs {passwordValidation.uppercase ? 'text-emerald-600 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}">
										<span class="mr-2 size-1.5 rounded-full {passwordValidation.uppercase ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}"></span>
										包含大写字母
									</div>
									<div class="flex items-center text-xs {passwordValidation.lowercase ? 'text-emerald-600 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}">
										<span class="mr-2 size-1.5 rounded-full {passwordValidation.lowercase ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}"></span>
										包含小写字母
									</div>
									<div class="flex items-center text-xs {passwordValidation.number ? 'text-emerald-600 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}">
										<span class="mr-2 size-1.5 rounded-full {passwordValidation.number ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}"></span>
										包含数字
									</div>
									<div class="flex items-center text-xs {passwordValidation.special ? 'text-emerald-600 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}">
										<span class="mr-2 size-1.5 rounded-full {passwordValidation.special ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}"></span>
										包含特殊字符
									</div>
								</div>
							{/if}
						</div>

						<div>
							<label for="confirm-password" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
								确认密码
							</label>
							<input
								id="confirm-password"
								name="confirm-password"
								type="password"
								autocomplete="new-password"
								required
								bind:value={confirmPassword}
								disabled={loading}
								class="w-full rounded-2xl border border-slate-200 bg-white/80 px-4 py-3 text-sm text-slate-950 outline-hidden transition placeholder:text-slate-400 focus:border-cyan-400 focus:ring-4 focus:ring-cyan-400/10 disabled:cursor-not-allowed disabled:opacity-60 dark:border-white/10 dark:bg-white/5 dark:text-white dark:placeholder:text-slate-500"
								placeholder="请再次输入密码"
							/>
							{#if confirmPassword && newPassword !== confirmPassword}
								<p class="mt-2 text-sm text-red-600 dark:text-red-300">密码不一致</p>
							{/if}
						</div>

						<button
							type="submit"
							disabled={loading || !isValidPassword || newPassword !== confirmPassword}
							class="flex w-full items-center justify-center rounded-2xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-slate-950/20 transition hover:-translate-y-0.5 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-cyan-300 dark:text-slate-950 dark:shadow-cyan-950/30 dark:hover:bg-cyan-200"
						>
							{#if loading}
								<Spinner className="mr-2 size-4" />
								重置中...
							{:else}
								确认重置密码
							{/if}
						</button>
					</form>

					<button
						type="button"
						class="mt-6 flex w-full justify-center rounded-2xl border border-slate-200 bg-white/70 px-4 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 dark:border-white/10 dark:bg-white/5 dark:text-slate-200 dark:hover:bg-white/10"
						on:click={() => goto('/auth')}
					>
						返回登录页面
					</button>
				</div>
			</section>
		</div>
	</div>
</div>

<style>
	.auth-reset-page {
		background:
			radial-gradient(circle at top left, rgba(34, 211, 238, 0.28), transparent 32rem),
			radial-gradient(circle at 78% 18%, rgba(59, 130, 246, 0.24), transparent 30rem),
			linear-gradient(135deg, #020617 0%, #0f172a 44%, #111827 100%);
	}

	.auth-reset-page::before {
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
