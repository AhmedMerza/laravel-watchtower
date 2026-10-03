<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

/**
 * Thin wrapper around Cloudflare's account-level IP Access Rules API
 * (POST/GET/DELETE /accounts/{account_id}/firewall/access_rules/rules).
 * CloudflareTarget decides WHAT to do; this class is only HOW to say it over
 * HTTP — the same split SyncSignature/PushBlockToMaster already use.
 *
 * Reads its credentials from config at the point of each call, not via the
 * constructor, so a test can `config()->set(...)` per case the same way
 * PushBlockToMaster's tests already do for sync config.
 *
 * Not `final`, deliberately — CloudflareTargetTest mocks this class directly
 * (Mockery can't mock a final class behind a type hint), the same way the
 * existing tests already mock LaravelTarget, which also isn't final.
 */
class CloudflareApi
{
    private const BASE_URL = 'https://api.cloudflare.com/client/v4';

    /**
     * Tags every rule Watchtower creates, so reconcile() can tell "ours" from
     * a rule the account owner added by hand — and never touch the latter.
     */
    public const NOTE = 'Managed by laravel-watchtower — do not edit by hand.';

    private const PER_PAGE = 100;

    /**
     * The single rule matching $target/$value, or null. At most one can ever
     * exist for a given target+value: Cloudflare rejects a second rule for
     * the same configuration regardless of mode or notes.
     *
     * @return array{id: string, mode: string, notes: ?string}|null
     */
    public function findRule(string $target, string $value): ?array
    {
        $response = $this->client()->get($this->rulesUrl(), [
            'configuration.target' => $target,
            'configuration.value'  => $value,
            'per_page'             => 5,
        ]);

        $this->throwUnlessSuccessful($response, "look up the rule for {$value}");

        $rules = $response->json('result') ?? [];

        if ($rules === []) {
            return null;
        }

        return [
            'id'    => $rules[0]['id'],
            'mode'  => $rules[0]['mode'],
            'notes' => $rules[0]['notes'] ?? null,
        ];
    }

    /**
     * Every rule Watchtower has ever tagged, across every page.
     *
     * @return array<string, string> value => rule id
     */
    public function listManaged(): array
    {
        $managed = [];
        $page = 1;

        do {
            $response = $this->client()->get($this->rulesUrl(), [
                // Best-effort server-side narrowing — correctness doesn't
                // depend on this filter being exact, since every result is
                // re-checked for an exact match below before being trusted.
                'notes'    => self::NOTE,
                'page'     => $page,
                'per_page' => self::PER_PAGE,
            ]);

            $this->throwUnlessSuccessful($response, 'list managed rules');

            $rules = $response->json('result') ?? [];

            foreach ($rules as $rule) {
                if (($rule['notes'] ?? null) === self::NOTE) {
                    $managed[$rule['configuration']['value']] = $rule['id'];
                }
            }

            $page++;
        } while (count($rules) === self::PER_PAGE);

        return $managed;
    }

    public function create(string $target, string $value): string
    {
        $response = $this->client()->post($this->rulesUrl(), [
            'mode'          => 'block',
            'notes'         => self::NOTE,
            'configuration' => ['target' => $target, 'value' => $value],
        ]);

        $this->throwUnlessSuccessful($response, "create a rule for {$value}");

        return (string) $response->json('result.id');
    }

    public function delete(string $ruleId): void
    {
        $response = $this->client()->delete("{$this->rulesUrl()}/{$ruleId}");

        $this->throwUnlessSuccessful($response, "delete rule {$ruleId}");
    }

    private function client(): PendingRequest
    {
        return Http::withToken((string) config('watchtower.block_targets.cloudflare.api_token'))
            ->acceptJson();
    }

    private function rulesUrl(): string
    {
        $accountId = (string) config('watchtower.block_targets.cloudflare.account_id');

        return self::BASE_URL."/accounts/{$accountId}/firewall/access_rules/rules";
    }

    private function throwUnlessSuccessful(Response $response, string $action): void
    {
        if (! $response->successful()) {
            throw new \RuntimeException("Cloudflare returned HTTP {$response->status()} while trying to {$action}.");
        }
    }
}
