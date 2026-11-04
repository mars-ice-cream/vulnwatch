<?php

namespace GlpiPlugin\Vulnwatch\Matching;

/**
 * Comparaison de versions selon l'écosystème.
 *
 * - generic : logiciels éditeurs (Windows, macOS, applications) — segments numériques
 *   comparés numériquement, pré-versions (alpha, beta, rc, pre, dev) avant la version finale ;
 * - dpkg    : algorithme Debian/Ubuntu (epoch:upstream-revision, tilde avant tout) ;
 * - rpm     : algorithme rpmvercmp (RHEL, SUSE…), simplifié sans epoch implicite.
 *
 * compare() retourne null quand une version n'est pas comparable : l'appelant doit alors
 * produire « Non évalué », jamais « Affecté » ni « Non affecté ».
 */
final class VersionComparator
{
    private const PRE_RELEASE = ['dev' => -4, 'alpha' => -3, 'a' => -3, 'beta' => -2, 'b' => -2, 'pre' => -1, 'preview' => -1, 'rc' => -1];

    public static function isComparable(?string $v): bool
    {
        return $v !== null && preg_match('/\d/', $v) === 1 && strlen($v) <= 128;
    }

    public static function compare(?string $a, ?string $b, string $scheme = 'generic'): ?int
    {
        if (!self::isComparable($a) || !self::isComparable($b)) {
            return null;
        }
        $a = trim((string) $a);
        $b = trim((string) $b);
        return match ($scheme) {
            'dpkg'  => self::dpkg($a, $b),
            'rpm'   => self::rpm($a, $b),
            default => self::generic($a, $b),
        };
    }

    /** @return list<int|string> */
    public static function genericSegments(string $v): array
    {
        $v = strtolower(trim($v));
        $v = preg_replace('/^v(?=\d)/', '', $v) ?? $v;
        // retire un suffixe de build entre parenthèses ou après « + » (métadonnées semver)
        $v = preg_replace('/\s*\(.*\)$|\+.*$/', '', $v) ?? $v;
        preg_match_all('/\d+|[a-z]+/', $v, $m);
        $out = [];
        foreach ($m[0] as $tok) {
            $out[] = ctype_digit($tok) ? (int) $tok : $tok;
        }
        return $out;
    }

    private static function generic(string $a, string $b): int
    {
        $sa = self::genericSegments($a);
        $sb = self::genericSegments($b);
        $n = max(count($sa), count($sb));
        for ($i = 0; $i < $n; $i++) {
            $x = $sa[$i] ?? null;
            $y = $sb[$i] ?? null;
            if ($x === $y || ($x === null && $y === 0) || ($y === null && $x === 0)) {
                continue;
            }
            $wx = self::weight($x);
            $wy = self::weight($y);
            if ($wx !== $wy) {
                return $wx <=> $wy;
            }
            if (is_int($x) && is_int($y)) {
                return $x <=> $y;
            }
            return strcmp((string) $x, (string) $y) <=> 0;
        }
        return 0;
    }

    /**
     * Poids d'un segment : absent = 0 (1.0 == 1.0.0), nombre = 1 (1.0.1 > 1.0),
     * pré-version < 0 (1.0rc1 < 1.0), autre suffixe alphabétique = 0.5 (1.0a-patch > 1.0).
     */
    private static function weight(int|string|null $s): float
    {
        if ($s === null) {
            return 0;
        }
        if (is_int($s)) {
            return 1;
        }
        return isset(self::PRE_RELEASE[$s]) ? self::PRE_RELEASE[$s] : 0.5;
    }

    // ---------- Debian ----------

    private static function dpkg(string $a, string $b): int
    {
        [$ea, $ua, $ra] = self::dpkgSplit($a);
        [$eb, $ub, $rb] = self::dpkgSplit($b);
        if ($ea !== $eb) {
            return $ea <=> $eb;
        }
        return self::dpkgPart($ua, $ub) ?: self::dpkgPart($ra, $rb);
    }

    /** @return array{0:int,1:string,2:string} */
    private static function dpkgSplit(string $v): array
    {
        $epoch = 0;
        if (preg_match('/^(\d+):(.*)$/', $v, $m)) {
            $epoch = (int) $m[1];
            $v = $m[2];
        }
        $rev = '0';
        $pos = strrpos($v, '-');
        if ($pos !== false) {
            $rev = substr($v, $pos + 1);
            $v = substr($v, 0, $pos);
        }
        return [$epoch, $v, $rev];
    }

    private static function dpkgOrder(string $c): int
    {
        if ($c === '~') {
            return -1;
        }
        if (ctype_digit($c)) {
            return 0;
        }
        if ($c === '') {
            return 0;
        }
        if (ctype_alpha($c)) {
            return ord($c);
        }
        return ord($c) + 256;
    }

    private static function dpkgPart(string $a, string $b): int
    {
        $i = $j = 0;
        $la = strlen($a);
        $lb = strlen($b);
        while ($i < $la || $j < $lb) {
            $diff = 0;
            while (($i < $la && !ctype_digit($a[$i])) || ($j < $lb && !ctype_digit($b[$j]))) {
                $ac = $i < $la ? self::dpkgOrder($a[$i]) : 0;
                $bc = $j < $lb ? self::dpkgOrder($b[$j]) : 0;
                if ($ac !== $bc) {
                    return $ac <=> $bc;
                }
                $i++;
                $j++;
            }
            while ($i < $la && $a[$i] === '0') {
                $i++;
            }
            while ($j < $lb && $b[$j] === '0') {
                $j++;
            }
            while ($i < $la && $j < $lb && ctype_digit($a[$i]) && ctype_digit($b[$j])) {
                if ($diff === 0) {
                    $diff = ord($a[$i]) - ord($b[$j]);
                }
                $i++;
                $j++;
            }
            if ($i < $la && ctype_digit($a[$i])) {
                return 1;
            }
            if ($j < $lb && ctype_digit($b[$j])) {
                return -1;
            }
            if ($diff !== 0) {
                return $diff <=> 0;
            }
        }
        return 0;
    }

    // ---------- RPM ----------

    private static function rpm(string $a, string $b): int
    {
        if ($a === $b) {
            return 0;
        }
        preg_match_all('/~|\^|\d+|[a-zA-Z]+/', $a, $ma);
        preg_match_all('/~|\^|\d+|[a-zA-Z]+/', $b, $mb);
        $sa = $ma[0];
        $sb = $mb[0];
        while ($sa !== [] || $sb !== []) {
            $x = array_shift($sa);
            $y = array_shift($sb);
            if ($x === '~' || $y === '~') {
                if ($x !== $y) {
                    return $x === '~' ? -1 : 1;
                }
                continue;
            }
            if ($x === null) {
                return -1;
            }
            if ($y === null) {
                return 1;
            }
            $dx = ctype_digit($x);
            $dy = ctype_digit($y);
            if ($dx !== $dy) {
                return $dx ? 1 : -1;
            }
            $c = $dx ? (ltrim($x, '0') === ltrim($y, '0') ? 0 : (strlen(ltrim($x, '0')) <=> strlen(ltrim($y, '0')) ?: strcmp(ltrim($x, '0'), ltrim($y, '0')))) : strcmp($x, $y);
            if ($c !== 0) {
                return $c <=> 0;
            }
        }
        return 0;
    }

    /** « 1:9.6p1-3ubuntu13.5 » → « 9.6p1 » ; « 3.0.2-0ubuntu1.18 » → « 3.0.2 » ; « 1.1.1k-12.el8 » → « 1.1.1k ». */
    public static function upstreamPart(string $v): string
    {
        $v = preg_replace('/^\d+:/', '', trim($v)) ?? $v;
        $pos = strrpos($v, '-');
        if ($pos !== false && $pos > 0) {
            $v = substr($v, 0, $pos);
        }
        return preg_replace('/(\+dfsg.*|\+deb.*|~.*)$/', '', $v) ?? $v;
    }

    /**
     * Indique une version empaquetée par une distribution Linux : les correctifs de sécurité
     * peuvent y être rétroportés sans changer la version amont, une plage NVD ne suffit donc pas.
     */
    public static function looksLikeDistroPackage(string $v): bool
    {
        return (bool) preg_match('/(ubuntu|deb\d|\+dfsg|\+deb|~bpo|\.el\d|\.fc\d+|\.amzn|\.suse|\.sles|\.mga\d|^\d+:)/i', $v)
            || (bool) preg_match('/^\d[0-9a-z.]*-\d[0-9a-z.+~]*$/i', $v); // upstream-révision
    }
}
