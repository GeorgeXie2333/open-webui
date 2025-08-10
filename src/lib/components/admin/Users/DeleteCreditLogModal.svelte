<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { createEventDispatcher } from 'svelte';
	import { getContext } from 'svelte';

	import Spinner from '$lib/components/common/Spinner.svelte';
	import Modal from '$lib/components/common/Modal.svelte';
	import XMark from '$lib/components/icons/XMark.svelte';
	import { deleteCreditLogs } from '$lib/apis/credit/index.js';

	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	export let show = false;

	let loading = false;

	let deleteTime = new Date();
	deleteTime.setMonth(new Date().getMonth() - 1);
	let input = deleteTime.toLocaleString();

	$: if (show) {
		deleteTime = new Date();
		deleteTime.setMonth(new Date().getMonth() - 6);
		input = deleteTime.toLocaleString();
	}

	const submitHandler = async () => {
		const stopLoading = () => {
			dispatch('save');
			loading = false;
		};

		loading = true;

		const _deleteTime = new Date(input);
		if (isNaN(_deleteTime.getTime())) {
			toast.error($i18n.t('Invalid date format'));
			loading = false;
			return;
		}

		const res = await deleteCreditLogs(
			localStorage.token,
			Math.floor(deleteTime.getTime() / 1000)
		).catch((error) => {
			toast.error(`${error}`);
		});
		if (res) {
			toast.success($i18n.t('Delete {{count}} Logs Successfully', { count: res.affect_rows }));
			stopLoading();
			show = false;
		}
		loading = false;
	};
</script>

<Modal size="sm" bind:show>
	<div>
		<div class=" flex justify-between dark:text-gray-300 px-5 pt-4">
			<div class=" text-lg font-medium self-center">{$i18n.t('Delete Logs')}</div>
			<button
				class="self-center"
				on:click={() => {
					show = false;
				}}
			>
				<XMark className={'size-5'} />
			</button>
		</div>

		<div class="flex flex-col md:flex-row w-full px-4 pb-3 md:space-x-4 dark:text-gray-200">
			<div class=" flex flex-col w-full sm:flex-row sm:justify-center sm:space-x-6">
				<form class="flex flex-col w-full" on:submit|preventDefault={() => submitHandler()}>
					<div class="px-1">
						<div class="flex flex-col w-full mb-3">
							<div class=" mb-2 text-xs text-gray-500">
								{$i18n.t('Delete Credit Logs Before This Time')}
							</div>

							<div class="flex-1">
								<input
									bind:value={input}
									type="text"
									class="w-full rounded-md h-[32px] bg-gray-50 dark:text-gray-300 dark:bg-gray-850 text-center font-medium"
								/>
							</div>
						</div>
					</div>

					<div class="flex justify-end text-sm font-medium">
						<button
							class="px-3.5 py-1.5 text-sm font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full flex flex-row space-x-1 items-center {loading
								? ' cursor-not-allowed'
								: ''}"
							type="submit"
							disabled={loading}
						>
							{$i18n.t('Delete')}

							{#if loading}
								<div class="ml-2 self-center">
									<Spinner />
								</div>
							{/if}
						</button>
					</div>
				</form>
			</div>
		</div>
	</div>
</Modal>

<style>
	input::-webkit-outer-spin-button,
	input::-webkit-inner-spin-button {
		/* display: none; <- Crashes Chrome on hover */
		-webkit-appearance: none;
		margin: 0; /* <-- Apparently some margin are still there even though it's hidden */
	}

	.tabs::-webkit-scrollbar {
		display: none; /* for Chrome, Safari and Opera */
	}

	.tabs {
		-ms-overflow-style: none; /* IE and Edge */
		scrollbar-width: none; /* Firefox */
	}

	input[type='number'] {
		-moz-appearance: textfield; /* Firefox */
	}
</style>
