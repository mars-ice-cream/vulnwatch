<?php

namespace GlpiPlugin\Vulnwatch;

/**
 * Paramètres globaux, stockés dans glpi_configs (contexte plugin:vulnwatch).
 */
final class Config
{
    public const CONTEXT = 'plugin:vulnwatch';

    public const DEFAULTS = [
        // Sources
        'nvd_enabled'          => '1',
        'nvd_api_key'          => '',
        'nvd_url'              => 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        // referenced = uniquement les CVE citées par les flux/ajoutées ; incremental = toutes les CVE modifiées
        'nvd_mode'             => 'referenced',
        'nvd_batch_size'       => '20',
        'nvd_last_sync'        => '',
        'kev_enabled'          => '1',
        'kev_track_all'        => '0',
        'kev_url'              => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'kev_last_sync'        => '',
        'kev_last_error'       => '',
        // Analyse
        'stale_days'           => '30',
        // Sécurité des récupérations HTTP
        'http_timeout'         => '20',
        'http_max_bytes'       => '5242880',
        'http_allowed_ports'   => '80,443',
        // Hôtes internes explicitement autorisés (un par ligne : nom d'hôte ou CIDR)
        'http_internal_allowlist' => '',
        'http_proxy'           => '',
    ];

    /** @var array<string,string>|null */
    private static ?array $cache = null;

    public static function installDefaults(): void
    {
        $current = \Config::getConfigurationValues(self::CONTEXT);
        $missing = array_diff_key(self::DEFAULTS, $current);
        if ($missing !== []) {
            \Config::setConfigurationValues(self::CONTEXT, $missing);
        }
        self::$cache = null;
    }

    public static function uninstall(): void
    {
        \Config::deleteConfigurationValues(self::CONTEXT, array_keys(self::DEFAULTS));
        self::$cache = null;
    }

    public static function get(string $key): string
    {
        if (self::$cache === null) {
            self::$cache = \Config::getConfigurationValues(self::CONTEXT) + self::DEFAULTS;
        }
        return (string) (self::$cache[$key] ?? self::DEFAULTS[$key] ?? '');
    }

    public static function getInt(string $key): int
    {
        return (int) self::get($key);
    }

    public static function getBool(string $key): bool
    {
        return self::get($key) === '1';
    }

    /** @param array<string,string|int> $values */
    public static function set(array $values): void
    {
        $values = array_intersect_key($values, self::DEFAULTS);
        \Config::setConfigurationValues(self::CONTEXT, array_map('strval', $values));
        self::$cache = null;
    }

    public static function reset(): void
    {
        self::$cache = null;
    }
}
