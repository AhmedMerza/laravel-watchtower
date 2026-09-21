{{--
    The management page shell.

    Self-contained on purpose: no CDN, no Google Fonts, no build step, no
    JavaScript. The one <style> block below is the whole stylesheet, so the
    page renders identically on an air-gapped host and cannot be broken by a
    third party's outage. A strict CSP still needs `style-src 'unsafe-inline'`
    for it; nothing here needs `script-src 'unsafe-inline'`.

    Token names match LogScope's so the two read as one product when both are
    installed. Colours are dark-first, with a light override driven by the
    operating system rather than a toggle — a toggle needs JavaScript and
    somewhere to remember the answer.
--}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>@yield('title', 'Watchtower')</title>
    <style>
        :root {
            --surface-0: #0a0a0b;
            --surface-1: #111113;
            --surface-2: #18181b;
            --surface-3: #27272a;
            --border: #3f3f46;
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent: #10b981;
            --danger: #f87171;
            --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
        }

        @media (prefers-color-scheme: light) {
            :root {
                --surface-0: #ffffff;
                --surface-1: #f8fafc;
                --surface-2: #f1f5f9;
                --surface-3: #e2e8f0;
                --border: #cbd5e1;
                --text-primary: #0f172a;
                --text-secondary: #475569;
                --text-muted: #64748b;
                --accent: #059669;
                --danger: #dc2626;
            }
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 0 1rem 4rem;
            font-family: var(--font-sans);
            font-size: 14px;
            line-height: 1.5;
            background: var(--surface-0);
            color: var(--text-primary);
        }

        .wrap { max-width: 1100px; margin: 0 auto; }

        header {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 1rem;
            flex-wrap: wrap;
            padding: 1.5rem 0 1rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }

        h1 { font-size: 1.125rem; font-weight: 600; margin: 0; }
        h1 .dot { color: var(--accent); }
        h2 { font-size: 0.9375rem; font-weight: 600; margin: 0 0 0.75rem; }

        .muted { color: var(--text-muted); }
        .secondary { color: var(--text-secondary); }
        .mono { font-family: var(--font-mono); }
        .nowrap { white-space: nowrap; }

        a { color: var(--accent); }

        .panel {
            background: var(--surface-1);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }

        label { display: block; font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 0.25rem; }

        input[type="text"], select {
            width: 100%;
            padding: 0.4rem 0.5rem;
            background: var(--surface-0);
            color: var(--text-primary);
            border: 1px solid var(--border);
            border-radius: 6px;
            font-family: inherit;
            font-size: 0.875rem;
        }

        input[type="text"]:focus, select:focus, button:focus {
            outline: 2px solid var(--accent);
            outline-offset: 1px;
        }

        button {
            font-family: inherit;
            font-size: 0.8125rem;
            padding: 0.4rem 0.75rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--surface-2);
            color: var(--text-primary);
            cursor: pointer;
        }

        button:hover { background: var(--surface-3); }

        button.primary {
            background: var(--accent);
            border-color: var(--accent);
            color: #04231a;
            font-weight: 600;
        }

        button.primary:hover { filter: brightness(1.08); }

        button.link {
            background: none;
            border: none;
            padding: 0.25rem 0;
            color: var(--danger);
            text-decoration: underline;
        }

        button.link:hover { background: none; filter: brightness(1.15); }

        table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }

        th {
            text-align: left;
            font-size: 0.6875rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            font-weight: 600;
            padding: 0 0.625rem 0.5rem;
            border-bottom: 1px solid var(--border);
        }

        td { padding: 0.625rem; border-bottom: 1px solid var(--surface-2); vertical-align: top; }
        tr:last-child td { border-bottom: none; }

        .badge {
            display: inline-block;
            font-size: 0.6875rem;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            border: 1px solid var(--border);
            background: var(--surface-2);
            color: var(--text-secondary);
            white-space: nowrap;
        }

        .badge.expired { color: var(--danger); border-color: var(--danger); }

        .notice {
            border: 1px solid var(--accent);
            border-left-width: 3px;
            border-radius: 6px;
            padding: 0.625rem 0.75rem;
            margin-bottom: 1rem;
        }

        .notice.error { border-color: var(--danger); }
        .notice ul { margin: 0; padding-left: 1.1rem; }

        .empty { padding: 2.5rem 1rem; text-align: center; color: var(--text-muted); }

        .row { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: flex-end; }
        .row > * { flex: 1 1 10rem; }
        .row > .narrow { flex: 0 0 auto; }

        .pager {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            padding-top: 1rem;
            font-size: 0.8125rem;
        }

        .pager a, .pager span.disabled {
            padding: 0.3rem 0.625rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            text-decoration: none;
        }

        .pager span.disabled { color: var(--text-muted); }

        .inline-form { display: inline; }
    </style>
</head>
<body>
    <div class="wrap">
        @yield('content')
    </div>
</body>
</html>
