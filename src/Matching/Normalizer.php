<?php

namespace GlpiPlugin\Vulnwatch\Matching;

/**
 * Normalisation des noms de logiciels et d'éditeurs tels que remontés par GLPI Agent.
 * Objectif : comparer « Mozilla Firefox (x64 fr) » et « mozilla:firefox » sans jamais
 * transformer une simple ressemblance en détection (la décision est prise par Mapper).
 */
final class Normalizer
{
    private const COMPANY_SUFFIXES = [
        'incorporated', 'inc', 'corporation', 'corp', 'co', 'company', 'ltd', 'limited', 'llc', 'gmbh', 'ag',
        'sa', 'sas', 'sarl', 'srl', 'bv', 'nv', 'ab', 'oy', 'as', 'plc', 'pty', 'kk', 'foundation', 'project',
        'team', 'the', 'software', 'systems', 'technologies', 'technology', 'international', 'group', 'contributors', 'developers',
    ];

    private const NAME_NOISE = [
        'x64', 'x86', 'x86_64', 'amd64', 'arm64', 'aarch64', 'i386', 'i686', '64bit', '32bit', '64-bit', '32-bit', 'x64-bit', '64', '32', 'bit',
        'en', 'us', 'fr', 'de', 'es', 'it', 'nl', 'pt', 'br', 'en-us', 'fr-fr', 'de-de', 'es-es', 'mui',
        'version', 'v', 'update', 'edition', 'setup', 'installer', 'msi', 'x', 'for', 'windows', 'win', 'win64', 'win32',
    ];

    public static function manufacturer(string $s): string
    {
        $s = self::base($s);
        $words = array_values(array_filter(explode(' ', $s), static fn($w) => $w !== '' && !in_array($w, self::COMPANY_SUFFIXES, true)));
        return implode(' ', $words);
    }

    /** Nom de logiciel sans version, architecture, langue ni mentions commerciales. */
    public static function softwareName(string $s): string
    {
        $s = self::base($s);
        $words = [];
        foreach (explode(' ', $s) as $w) {
            if ($w === '' || in_array($w, self::NAME_NOISE, true)) {
                continue;
            }
            // Jetons de version (1.2.3, 115.0, v2) et années isolées laissées (ex. « office 2016 » est significatif)
            if (preg_match('/^v?\d+([.\-_]\d+)+[a-z0-9]*$/', $w)) {
                continue;
            }
            $words[] = $w;
        }
        return implode(' ', $words);
    }

    /** Produit CPE (« acrobat_reader_dc ») vers forme comparable (« acrobat reader dc »). */
    public static function cpeToken(string $s): string
    {
        return self::base(str_replace(['_', '\\'], [' ', ''], $s));
    }

    private static function base(string $s): string
    {
        $s = mb_strtolower(trim($s));
        $s = str_replace(['®', '™', '©', '(r)', '(tm)'], ' ', $s);
        if (class_exists(\Normalizer::class)) {
            $s = \Normalizer::normalize($s, \Normalizer::FORM_D) ?: $s;
            $s = preg_replace('/\p{Mn}+/u', '', $s) ?? $s;
        }
        // garde + (notepad++) et les lettres/chiffres, le reste devient séparateur
        $s = preg_replace('/[^a-z0-9+.\-_ ]+/u', ' ', $s) ?? $s;
        $s = str_replace('_', ' ', $s);
        // séparateurs isolés ou en bord de mot (« - », « fin. ») ; conservés dans « 7-zip », « 1.2.3 »
        $s = preg_replace('/(?<=\s|^)[.\-]+|[.\-]+(?=\s|$)/', ' ', $s) ?? $s;
        return trim(preg_replace('/\s+/', ' ', $s) ?? $s);
    }

    /** Jetons significatifs, pour les comparaisons d'inclusion. @return list<string> */
    public static function tokens(string $normalized): array
    {
        return array_values(array_filter(explode(' ', $normalized), static fn($w) => $w !== ''));
    }
}
