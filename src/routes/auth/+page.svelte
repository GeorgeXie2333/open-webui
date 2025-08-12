<script>
    import DOMPurify from 'dompurify';
    import { marked } from 'marked';
    import { toast } from 'svelte-sonner';
    import { onMount, getContext, tick } from 'svelte';
    import { goto } from '$app/navigation';
    import { page } from '$app/stores';
    import { getBackendConfig } from '$lib/apis';
    import { ldapUserSignIn, getSessionUser, userSignIn, userSignUp } from '$lib/apis/auths';
    import { WEBUI_API_BASE_URL, WEBUI_BASE_URL } from '$lib/constants';
    import { WEBUI_NAME, config, user, socket } from '$lib/stores';
    import { generateInitialsImage, canvasPixelTest } from '$lib/utils';
    import Spinner from '$lib/components/common/Spinner.svelte';
    import OnBoarding from '$lib/components/OnBoarding.svelte';
    import SensitiveInput from '$lib/components/common/SensitiveInput.svelte';
    import ReCaptcha from '$lib/components/auth/ReCaptcha.svelte';

    const i18n = getContext('i18n');

    let loaded = false;
    let mode = $config?.features.enable_ldap ? 'ldap' : 'signin';
    let name = '';
    let email = '';
    let password = '';
    let confirmPassword = '';
    let recaptchaToken = '';
    let ldapUsername = '';
    let recaptchaComponent;

    const querystringValue = (key) => {
        const querystring = window.location.search;
        const urlParams = new URLSearchParams(querystring);
        return urlParams.get(key);
    };

    const setSessionUser = async (sessionUser) => {
        if (sessionUser) {
            console.log(sessionUser);
            toast.success($i18n.t(`You're now logged in.`));
            if (sessionUser.token) {
                localStorage.token = sessionUser.token;
            }
            $socket.emit('user-join', { auth: { token: sessionUser.token } });
            await user.set(sessionUser);
            await config.set(await getBackendConfig());
            const redirectPath = querystringValue('redirect') || '/';
            goto(redirectPath);
        }
    };

    const signInHandler = async () => {
        const sessionUser = await userSignIn(email, password).catch((error) => {
            toast.error(`${error}`);
            return null;
        });
        await setSessionUser(sessionUser);
    };

    const signUpHandler = async () => {
        if ($config?.features?.enable_signup_password_confirmation) {
            if (password !== confirmPassword) {
                toast.error($i18n.t('Passwords do not match.'));
                return;
            }
        }
        if ($config?.ENABLE_RECAPTCHA && mode === 'signup' && !recaptchaToken) {
            toast.error('请完成reCAPTCHA验证');
            return;
        }
        const sessionUser = await userSignUp(name, email, password, generateInitialsImage(name), recaptchaToken).catch(
            (error) => {
                toast.error(`${error}`);
                if (recaptchaComponent) {
                    recaptchaComponent.reset();
                    recaptchaToken = '';
                }
                return null;
            }
        );
        await setSessionUser(sessionUser);
    };

    const ldapSignInHandler = async () => {
        const sessionUser = await ldapUserSignIn(ldapUsername, password).catch((error) => {
            toast.error(`${error}`);
            return null;
        });
        await setSessionUser(sessionUser);
    };

    const submitHandler = async () => {
        if (mode === 'ldap') {
            await ldapSignInHandler();
        } else if (mode === 'signin') {
            await signInHandler();
        } else {
            await signUpHandler();
        }
    };

    const checkOauthCallback = async () => {
        function getCookie(name) {
            const match = document.cookie.match(
                new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)')
            );
            return match ? decodeURIComponent(match[1]) : null;
        }
        const token = getCookie('token');
        if (!token) {
            return;
        }
        const sessionUser = await getSessionUser(token).catch((error) => {
            toast.error(`${error}`);
            return null;
        });
        if (!sessionUser) {
            return;
        }
        localStorage.token = token;
        await setSessionUser(sessionUser);
    };

    let onboarding = false;

    async function setLogoImage() {
        await tick();
        const logo = document.getElementById('logo');
        if (logo) {
            const isDarkMode = document.documentElement.classList.contains('dark');
            if (isDarkMode) {
                const darkImage = new Image();
                darkImage.src = `${WEBUI_BASE_URL}/static/favicon-dark.png`;
                darkImage.onload = () => {
                    logo.src = `${WEBUI_BASE_URL}/static/favicon-dark.png`;
                    logo.style.filter = '';
                };
                darkImage.onerror = () => {
                    logo.style.filter = 'invert(1)';
                };
            }
        }
    }

    const handleRecaptchaVerified = (event) => {
        recaptchaToken = event.detail.token;
    };

    const handleRecaptchaExpired = () => {
        recaptchaToken = '';
        toast.warning('reCAPTCHA已过期，请重新验证');
    };

    const handleRecaptchaError = () => {
        recaptchaToken = '';
        toast.error('reCAPTCHA验证出错，请刷新页面重试');
    };

    onMount(async () => {
        if ($user !== undefined) {
            const redirectPath = querystringValue('redirect') || '/';
            goto(redirectPath);
        }
        await checkOauthCallback();
        loaded = true;
        setLogoImage();
        if (($config?.features.auth_trusted_header ?? false) || $config?.features.auth === false) {
            await signInHandler();
        } else {
            onboarding = $config?.onboarding ?? false;
        }
    });
</script>

<svelte:head>
    <title>
        {`${$WEBUI_NAME}`}
    </title>
</svelte:head>

<OnBoarding
    bind:show={onboarding}
    getStartedHandler={() => {
        onboarding = false;
        mode = $config?.features.enable_ldap ? 'ldap' : 'signup';
    }}
/>

<div class="w-full h-screen max-h-[100dvh] text-white relative auth-page">
    <div class="w-full absolute top-0 left-0 right-0 h-8 drag-region" />
    {#if loaded}
        <div class="fixed bg-transparent min-h-screen w-full flex justify-center font-primary z-50 text-black dark:text-white">
            <div class="w-full px-10 min-h-screen flex flex-col text-center">
                {#if ($config?.features.auth_trusted_header ?? false) || $config?.features.auth === false}
                    <div class=" my-auto pb-10 w-full sm:max-w-md">
                        <div class="flex items-center justify-center gap-3 text-xl sm:text-2xl text-center font-semibold dark:text-gray-200">
                            <div>
                                {$i18n.t('Signing in to {{WEBUI_NAME}}', { WEBUI_NAME: $WEBUI_NAME })}
                            </div>
                            <div>
                                <Spinner className="size-5" />
                            </div>
                        </div>
                    </div>
                {:else}
                    <div class="my-auto flex flex-col justify-center items-center">
                        <div class=" sm:max-w-md my-auto pb-10 w-full dark:text-gray-100">
                            {#if $config?.metadata?.auth_logo_position === 'center'}
                                <div class="flex justify-center mb-6">
                                    <img
                                        id="logo"
                                        crossorigin="anonymous"
                                        src="{WEBUI_BASE_URL}/static/favicon.png"
                                        class="size-24 rounded-full"
                                        alt=""
                                    />
                                </div>
                            {/if}
                            <form
                                class="flex flex-col justify-center"
                                on:submit={(e) => {
                                    e.preventDefault();
                                    submitHandler();
                                }}
                            >
                                <div class="mb-1 text-2xl font-medium">
                                    {#if $config?.onboarding ?? false}
                                        {$i18n.t(`Get started with {{WEBUI_NAME}}`, { WEBUI_NAME: $WEBUI_NAME })}
                                    {:else if mode === 'ldap'}
                                        {$i18n.t(`Sign in to {{WEBUI_NAME}} with LDAP`, { WEBUI_NAME: $WEBUI_NAME })}
                                    {:else if mode === 'signin'}
                                        {$i18n.t(`Sign in to {{WEBUI_NAME}}`, { WEBUI_NAME: $WEBUI_NAME })}
                                    {:else}
                                        {$i18n.t(`Sign up to {{WEBUI_NAME}}`, { WEBUI_NAME: $WEBUI_NAME })}
                                    {/if}
                                </div>

                                {#if $config?.onboarding ?? false}
                                    <div class="mt-1 text-xs font-medium text-gray-600 dark:text-gray-500">
                                        ⓘ {$WEBUI_NAME} {$i18n.t('does not make any external connections, and your data stays securely on your locally hosted server.')}
                                    </div>
                                {/if}

                                {#if $config?.features.enable_login_form || $config?.features.enable_ldap}
                                    <div class="flex flex-col mt-4">

                                        {#if mode === 'signup'}
                                            <div class="mb-2">
                                                <label for="name" class="text-sm font-medium text-left mb-1 block">{$i18n.t('Name')}</label>
                                                <input
                                                    bind:value={name}
                                                    type="text"
                                                    id="name"
                                                    class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
                                                    autocomplete="name"
                                                    placeholder={$i18n.t('Enter Your Full Name')}
                                                    required
                                                />
                                            </div>
                                        {/if}

                                        {#if mode === 'ldap'}
                                            <div class="mb-2">
                                                <label for="username" class="text-sm font-medium text-left mb-1 block">{$i18n.t('Username')}</label>
                                                <input
                                                    bind:value={ldapUsername}
                                                    type="text"
                                                    class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
                                                    autocomplete="username"
                                                    name="username"
                                                    id="username"
                                                    placeholder={$i18n.t('Enter Your Username')}
                                                    required
                                                />
                                            </div>
                                        {:else}
                                            <div class="mb-2">
                                                <label for="email" class="text-sm font-medium text-left mb-1 block">{$i18n.t('Email')}</label>
                                                <input
                                                    bind:value={email}
                                                    type="email"
                                                    id="email"
                                                    class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
                                                    autocomplete="email"
                                                    name="email"
                                                    placeholder={$i18n.t('Enter Your Email')}
                                                    required
                                                />
                                            </div>
                                        {/if}

                                        <div class="mb-2">
                                            <label for="password" class="text-sm font-medium text-left mb-1 block">{$i18n.t('Password')}</label>
                                            <SensitiveInput
                                                bind:value={password}
                                                type="password"
                                                id="password"
                                                class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
                                                placeholder={$i18n.t('Enter Your Password')}
                                                autocomplete={mode === 'signup' ? 'new-password' : 'current-password'}
                                                name="password"
                                                required
                                            />
                                            {#if mode === 'signin'}
                                                <div class="mt-1 text-right">
                                                    <button
                                                        type="button"
                                                        class="text-xs text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white underline"
                                                        on:click={() => goto('/auth/forgot-password')}
                                                    >
                                                        忘记密码？
                                                    </button>
                                                </div>
                                            {/if}
                                        </div>

                                        {#if mode === 'signup' && $config?.features?.enable_signup_password_confirmation}
                                            <div class="mt-2">
                                                <label for="confirm-password" class="text-sm font-medium text-left mb-1 block">{$i18n.t('Confirm Password')}</label>
                                                <SensitiveInput
                                                    bind:value={confirmPassword}
                                                    type="password"
                                                    id="confirm-password"
                                                    class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
                                                    placeholder={$i18n.t('Confirm Your Password')}
                                                    autocomplete="new-password"
                                                    name="confirm-password"
                                                    required
                                                />
                                            </div>
                                        {/if}

                                        {#if mode === 'signup' && $config?.ENABLE_RECAPTCHA && $config?.RECAPTCHA_SITE_KEY}
                                            <ReCaptcha
                                                bind:this={recaptchaComponent}
                                                siteKey={$config.RECAPTCHA_SITE_KEY}
                                                theme="light"
                                                on:verified={handleRecaptchaVerified}
                                                on:expired={handleRecaptchaExpired}
                                                on:error={handleRecaptchaError}
                                            />
                                        {/if}
                                    </div>
                                {/if}

                                <div class="mt-5">
                                    {#if $config?.features.enable_login_form || $config?.features.enable_ldap}
                                        {#if mode === 'ldap'}
                                            <button
                                                class="bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
                                                type="submit"
                                            >
                                                {$i18n.t('Authenticate')}
                                            </button>
                                        {:else}
                                            <button
                                                class="bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
                                                type="submit"
                                            >
                                                {mode === 'signin'
                                                    ? $i18n.t('Sign in')
                                                    : ($config?.onboarding ?? false)
                                                        ? $i18n.t('Create Admin Account')
                                                        : $i18n.t('Create Account')}
                                            </button>
                                            {#if $config?.features.enable_signup && !($config?.onboarding ?? false)}
                                                <div class=" mt-4 text-sm text-center">
                                                    {mode === 'signin'
                                                        ? $i18n.t("Don't have an account?")
                                                        : $i18n.t('Already have an account?')}
                                                    <button
                                                        class=" font-medium underline"
                                                        type="button"
                                                        on:click={() => {
                                                            if (mode === 'signin') {
                                                                mode = 'signup';
                                                            } else {
                                                                mode = 'signin';
                                                            }
                                                        }}
                                                    >
                                                        {mode === 'signin' ? $i18n.t('Sign up') : $i18n.t('Sign in')}
                                                    </button>
                                                </div>
                                            {/if}
                                        {/if}
                                    {/if}
                                </div>
                            </form>

                            {#if Object.keys($config?.oauth?.providers ?? {}).length > 0}
                                <div class="inline-flex items-center justify-center w-full">
                                    <hr class="w-32 h-px my-4 border-0 dark:bg-gray-100/10 bg-gray-700/10" />
                                    {#if $config?.features.enable_login_form || $config?.features.enable_ldap}
                                        <span class="px-3 text-sm font-medium text-gray-900 dark:text-white bg-transparent">{$i18n.t('or')}</span>
                                    {/if}
                                    <hr class="w-32 h-px my-4 border-0 dark:bg-gray-100/10 bg-gray-700/10" />
                                </div>
                                <div class="flex flex-col space-y-2">
                                    {#each Object.entries($config?.oauth?.providers ?? {}) as [provider, enabled]}
                                        {#if enabled}
                                            <button
                                                class="flex justify-center items-center bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
                                                on:click={() => {
                                                    window.location.href = `${WEBUI_BASE_URL}/oauth/${provider}/login`;
                                                }}
                                            >
                                                <span>{$i18n.t('Continue with {{provider}}', { provider })}</span>
                                            </button>
                                        {/if}
                                    {/each}
                                </div>
                            {/if}

                            {#if $config?.features.enable_ldap && $config?.features.enable_login_form}
                                <div class="mt-2">
                                    <button
                                        class="flex justify-center items-center text-xs w-full text-center underline"
                                        type="button"
                                        on:click={() => {
                                            if (mode === 'ldap')
                                                mode = ($config?.onboarding ?? false) ? 'signup' : 'signin';
                                            else mode = 'ldap';
                                        }}
                                    >
                                        <span>{mode === 'ldap' ? $i18n.t('Continue with Email') : $i18n.t('Continue with LDAP')}</span>
                                    </button>
                                </div>
                            {/if}
                        </div>

                        {#if $config?.metadata?.login_footer}
                            <div class="max-w-3xl mx-auto">
                                <div class="mt-2 text-[0.7rem] text-gray-500 dark:text-gray-400 marked">
                                    {@html DOMPurify.sanitize(marked($config?.metadata?.login_footer))}
                                </div>
                            </div>
                        {/if}
                    </div>
                {/if}
            </div>
        </div>
        {#if !$config?.metadata?.auth_logo_position}
            <div class="fixed m-10 z-50">
                <div class="flex space-x-2">
                    <div class=" self-center">
                        <img
                            id="logo"
                            crossorigin="anonymous"
                            src="{WEBUI_BASE_URL}/static/favicon.png"
                            class=" w-6 rounded-full"
                            alt=""
                        />
                    </div>
                </div>
            </div>
        {/if}
    {/if}
</div>

<style>
    .auth-page {
        background-color: white !important;
        background-image: url('/static/banner.jpg');
        background-repeat: no-repeat;
        background-position: top center;
        background-size: 100% auto;
        background-attachment: fixed;
    }
    /* 确保暗色主题下背景也是白色 */
    :global(.dark) .auth-page {
        background-color: white !important;
    }
</style>
