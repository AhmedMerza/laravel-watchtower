<?php

declare(strict_types=1);

namespace Watchtower\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * How many auto-blocks an address has earned, and when it last earned one.
 *
 * @property string $id
 * @property string $ip
 * @property string $scope '' = global, otherwise a declared scope name
 * @property int $offence_count
 * @property Carbon|null $first_offence_at
 * @property Carbon|null $last_offence_at
 */
class IpOffence extends Model
{
    use HasUlids;

    protected $table = 'ip_offences';

    /** first_offence_at and last_offence_at say this already, by name. */
    public $timestamps = false;

    protected $fillable = [
        'ip',
        'scope',
        'offence_count',
        'first_offence_at',
        'last_offence_at',
    ];

    protected $casts = [
        'offence_count'    => 'integer',
        'first_offence_at' => 'datetime',
        'last_offence_at'  => 'datetime',
    ];
}
