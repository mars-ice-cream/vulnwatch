<?php

namespace GlpiPlugin\Vulnwatch\Source;

/** Analyse d'une chaîne CPE 2.3 (forme formatée « cpe:2.3:… »). */
final class Cpe
{
    private const FIELDS = ['part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other'];

    /** @return array<string,string>|null */
    public static function parse(string $cpe): ?array
    {
        if (!str_starts_with($cpe, 'cpe:2.3:')) {
            return null;
        }
        // Découpe sur « : » non échappés
        $parts = preg_split('/(?<!\\\\):/', substr($cpe, 8));
        if ($parts === false || count($parts) < 3) {
            return null;
        }
        $parts = array_pad($parts, count(self::FIELDS), '*');
        $out = [];
        foreach (self::FIELDS as $i => $name) {
            $out[$name] = self::unescape($parts[$i]);
        }
        if (!in_array($out['part'], ['a', 'o', 'h'], true)) {
            return null;
        }
        return $out;
    }

    public static function unescape(string $s): string
    {
        return preg_replace('/\\\\(.)/', '$1', $s) ?? $s;
    }
}
