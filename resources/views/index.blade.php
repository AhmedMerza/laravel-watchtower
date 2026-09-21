{{--
    Blocked addresses: list, block, unblock.

    Every action is a plain form POST. The unblock confirmation is a round
    trip rather than a confirm() dialog, so it works with JavaScript disabled
    and needs no inline script — see layout.blade.php.
--}}
@extends('watchtower::layout')

@section('title', 'Watchtower — Blocked Addresses')

@section('content')
    @php
        $durationLabels = [
            '1h'        => '1 hour',
            '24h'       => '24 hours',
            '7d'        => '7 days',
            'permanent' => 'Permanent',
        ];
        $filters = array_filter([
            'source' => $source,
            'state'  => $state === 'active' ? null : $state,
        ]);
    @endphp

    <header>
        <h1>Watchtower <span class="dot">·</span> Blocked Addresses</h1>
        {{-- Fully qualified: a package view can't assume the app kept Laravel's class aliases. --}}
        <span class="muted">{{ $blocks->total() }} {{ \Illuminate\Support\Str::plural('block', $blocks->total()) }} {{ $state === 'all' ? 'in total' : $state }}</span>
    </header>

    @if (session('watchtower_status'))
        <div class="notice">{{ session('watchtower_status') }}</div>
    @endif

    @if ($errors->any())
        <div class="notice error">
            <ul>
                @foreach ($errors->all() as $error)
                    <li>{{ $error }}</li>
                @endforeach
            </ul>
        </div>
    @endif

    <div class="panel">
        <h2>Block an address</h2>
        <form method="POST" action="{{ route('watchtower.ui.block') }}">
            @csrf
            <div class="row">
                <div>
                    <label for="ip">IP address or CIDR range</label>
                    <input type="text" id="ip" name="ip" class="mono" value="{{ old('ip') }}"
                           placeholder="203.0.113.4 or 203.0.113.0/24" required>
                </div>
                <div>
                    <label for="reason">Reason</label>
                    <input type="text" id="reason" name="reason" value="{{ old('reason') }}"
                           placeholder="Optional" maxlength="500">
                </div>
                <div class="narrow">
                    <label for="duration">Duration</label>
                    <select id="duration" name="duration">
                        @foreach ($durations as $duration)
                            <option value="{{ $duration }}" @selected(old('duration', '24h') === $duration)>
                                {{ $durationLabels[$duration] ?? $duration }}
                            </option>
                        @endforeach
                    </select>
                </div>
                @if ($scopes !== [])
                    <div class="narrow">
                        <label for="scope">Applies to</label>
                        <select id="scope" name="scope">
                            <option value="">The whole app</option>
                            @foreach ($scopes as $declared)
                                <option value="{{ $declared }}" @selected(old('scope') === $declared)>
                                    {{ $declared }} routes
                                </option>
                            @endforeach
                        </select>
                    </div>
                @endif
                <div class="narrow">
                    <button type="submit" class="primary">Block</button>
                </div>
            </div>
            <div style="margin-top: 0.625rem;">
                <label style="display: flex; align-items: center; gap: 0.4rem;">
                    <input type="checkbox" name="force" value="1" @checked(old('force'))>
                    <span>Allow a range wider than /16 (IPv4) or /32 (IPv6)</span>
                </label>
            </div>
        </form>
    </div>

    <div class="panel">
        <form method="GET" action="{{ route('watchtower.ui.index') }}">
            <div class="row">
                <div class="narrow">
                    <label for="filter-source">Source</label>
                    <select id="filter-source" name="source">
                        <option value="">Any source</option>
                        @foreach ($sources as $case)
                            <option value="{{ $case->value }}" @selected($source === $case->value)>{{ $case->value }}</option>
                        @endforeach
                    </select>
                </div>
                <div class="narrow">
                    <label for="filter-state">Showing</label>
                    <select id="filter-state" name="state">
                        <option value="active" @selected($state === 'active')>Active</option>
                        <option value="expired" @selected($state === 'expired')>Expired</option>
                        <option value="all" @selected($state === 'all')>All</option>
                    </select>
                </div>
                <div class="narrow">
                    <button type="submit">Filter</button>
                </div>
            </div>
        </form>

        @if ($blocks->isEmpty())
            <div class="empty">
                @if ($filters === [])
                    Nothing is blocked.
                @else
                    No blocks match these filters.
                @endif
            </div>
        @else
            <table style="margin-top: 1rem;">
                <thead>
                    <tr>
                        <th>Address</th>
                        <th>Source</th>
                        <th>Reason</th>
                        <th>Blocked by</th>
                        <th>Blocked</th>
                        <th>Expires</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($blocks as $block)
                        <tr>
                            <td class="mono nowrap">
                                {{ $block->ip }}
                                @if ($block->scope !== '')
                                    <br><span class="badge">{{ $block->scope }} routes</span>
                                @endif
                            </td>
                            <td class="nowrap">
                                <span class="badge">{{ $block->source->value }}</span>
                                @if ($block->source_env)
                                    <br><span class="muted">{{ $block->source_env }}</span>
                                @endif
                            </td>
                            <td class="secondary">
                                {{ $block->reason ?: '—' }}
                                @if ($block->log_entry_id && $logScopeUrl)
                                    <br><a href="{{ $logScopeUrl }}?log={{ $block->log_entry_id }}">View log entry</a>
                                @endif
                            </td>
                            <td class="secondary">{{ $block->blocked_by ?: '—' }}</td>
                            <td class="muted nowrap" title="{{ $block->created_at }}">
                                {{ $block->created_at?->diffForHumans() ?? '—' }}
                            </td>
                            <td class="nowrap" @if ($block->expires_at) title="{{ $block->expires_at }}" @endif>
                                @if ($block->expires_at === null)
                                    Never
                                @elseif ($block->isExpired())
                                    <span class="badge expired">expired {{ $block->expires_at->diffForHumans() }}</span>
                                @else
                                    {{ $block->expires_at->diffForHumans() }}
                                @endif
                            </td>
                            <td class="nowrap" style="text-align: right;">
                                @if ($confirm === $block->id)
                                    <form method="POST" action="{{ route('watchtower.ui.unblock') }}" class="inline-form">
                                        @csrf
                                        <input type="hidden" name="id" value="{{ $block->id }}">
                                        <button type="submit" class="primary">Unblock</button>
                                    </form>
                                    <a href="{{ route('watchtower.ui.index', $filters + ['page' => $blocks->currentPage()]) }}">Cancel</a>
                                @else
                                    <a href="{{ route('watchtower.ui.index', $filters + ['page' => $blocks->currentPage(), 'confirm' => $block->id]) }}">Unblock</a>
                                @endif
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>

            @if ($blocks->lastPage() > 1)
                <div class="pager">
                    @if ($blocks->previousPageUrl())
                        <a href="{{ $blocks->previousPageUrl() }}" rel="prev">Previous</a>
                    @else
                        <span class="disabled">Previous</span>
                    @endif

                    <span class="muted">Page {{ $blocks->currentPage() }} of {{ $blocks->lastPage() }}</span>

                    @if ($blocks->nextPageUrl())
                        <a href="{{ $blocks->nextPageUrl() }}" rel="next">Next</a>
                    @else
                        <span class="disabled">Next</span>
                    @endif
                </div>
            @endif
        @endif
    </div>
@endsection
