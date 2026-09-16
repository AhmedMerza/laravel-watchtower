{{--
    Watchtower — IP Actions partial
    Included via @includeIf('watchtower::partials.ip-actions') in detail-panel.blade.php.
    Renders nothing if Watchtower is disabled or its API routes aren't registered.
--}}
@php
    // Built from the registered route names, not by rewriting LogScope's API
    // base: the mount prefix is config-driven and changed once already, which
    // left the button posting to a path that no longer existed. Relative URLs,
    // so a stale APP_URL can't aim the fetch at another host. `__IP__` is a
    // placeholder the client substitutes per selected log.
    $watchtowerUrls = \Illuminate\Support\Facades\Route::has('watchtower.api.block')
        ? [
            'block'   => route('watchtower.api.block', absolute: false),
            'unblock' => route('watchtower.api.unblock', ['ip' => '__IP__'], absolute: false),
            'status'  => route('watchtower.api.status', ['ip' => '__IP__'], absolute: false),
        ]
        : null;
@endphp
@if(config('watchtower.enabled', false) && $watchtowerUrls)
<div x-data="watchtowerIpActions(@js($watchtowerUrls))"
     x-init="init()"
     @logscope:log-selected.window="onLogSelected($event.detail.log)">

    <template x-if="currentIp">
        <div class="px-4 py-2 border-t border-[var(--border)]">

            {{-- Blocked state --}}
            <template x-if="blockStatus === 'blocked'">
                <div class="flex items-center gap-2">
                    <div class="flex-1 flex items-center gap-2 px-3 h-9 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm font-medium">
                        <svg class="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clip-rule="evenodd"/>
                        </svg>
                        <span>Blocked <span x-show="blockedSince" class="font-mono text-xs opacity-75" x-text="'since ' + blockedSince"></span></span>
                    </div>
                    <button @click="unblock()"
                        :disabled="loading"
                        class="h-9 px-3 rounded-lg text-sm font-medium text-[var(--text-muted)] bg-[var(--surface-2)] hover:bg-[var(--surface-3)] border border-[var(--border)] transition-colors disabled:opacity-50">
                        Unblock
                    </button>
                </div>
            </template>

            {{-- Unblocked state --}}
            <template x-if="blockStatus === 'unblocked'">
                <div>
                    <template x-if="!confirming">
                        <button @click="confirming = true"
                            :disabled="loading"
                            class="w-full h-9 px-3 rounded-lg text-sm font-medium text-amber-400 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 transition-colors disabled:opacity-50">
                            Block IP <span class="font-mono opacity-75" x-text="currentIp"></span>
                        </button>
                    </template>

                    <template x-if="confirming">
                        <div class="flex items-center gap-2">
                            <span class="flex-1 text-xs text-[var(--text-muted)]">Block <span class="font-mono text-amber-400" x-text="currentIp"></span>?</span>
                            <button @click="block()"
                                :disabled="loading"
                                class="h-9 px-3 rounded-lg text-sm font-medium text-white bg-red-600 hover:bg-red-700 transition-colors disabled:opacity-50">
                                Confirm
                            </button>
                            <button @click="confirming = false"
                                class="h-9 px-3 rounded-lg text-sm font-medium btn-ghost">
                                Cancel
                            </button>
                        </div>
                    </template>
                </div>
            </template>

            {{-- Loading skeleton --}}
            <template x-if="blockStatus === null">
                <div class="w-full h-9 rounded-lg bg-[var(--surface-2)] animate-pulse"></div>
            </template>
        </div>
    </template>
</div>

<script>
function watchtowerIpActions(urls) {
    return {
        urls,
        currentIp: null,
        blockStatus: null,  // null=loading, 'blocked', 'unblocked'
        blockedSince: null,
        confirming: false,
        loading: false,

        init() {},

        onLogSelected(log) {
            this.currentIp = log?.ip_address ?? null;
            this.blockStatus = null;
            this.blockedSince = null;
            this.confirming = false;

            if (this.currentIp) {
                this.checkStatus();
            }
        },

        // The server hands us the routes; only the IP is filled in here.
        urlFor(name, ip) {
            return this.urls[name].replace('__IP__', encodeURIComponent(ip));
        },

        async checkStatus() {
            try {
                const res = await fetch(this.urlFor('status', this.currentIp), {
                    headers: { Accept: 'application/json' }
                });
                if (!res.ok) { this.blockStatus = 'unblocked'; return; }
                const json = await res.json();
                this.blockStatus = json.blocked ? 'blocked' : 'unblocked';
                if (json.blocked && json.data?.created_at) {
                    this.blockedSince = new Date(json.data.created_at).toLocaleDateString();
                }
            } catch {
                this.blockStatus = 'unblocked';
            }
        },

        async block() {
            if (!this.currentIp || this.loading) return;
            this.loading = true;
            try {
                const res = await fetch(this.urls.block, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        Accept: 'application/json',
                        'X-XSRF-TOKEN': this.getCsrfToken(),
                    },
                    body: JSON.stringify({ ip: this.currentIp }),
                });
                if (res.ok) {
                    this.blockStatus = 'blocked';
                    this.blockedSince = new Date().toLocaleDateString();
                }
            } finally {
                this.loading = false;
                this.confirming = false;
            }
        },

        async unblock() {
            if (!this.currentIp || this.loading) return;
            this.loading = true;
            try {
                const res = await fetch(this.urlFor('unblock', this.currentIp), {
                    method: 'DELETE',
                    headers: {
                        Accept: 'application/json',
                        'X-XSRF-TOKEN': this.getCsrfToken(),
                    },
                });
                if (res.ok) {
                    this.blockStatus = 'unblocked';
                    this.blockedSince = null;
                }
            } finally {
                this.loading = false;
            }
        },

        getCsrfToken() {
            return decodeURIComponent(
                document.cookie.split(';')
                    .find(c => c.trim().startsWith('XSRF-TOKEN='))
                    ?.split('=')[1] ?? ''
            );
        },
    };
}
</script>
@endif
