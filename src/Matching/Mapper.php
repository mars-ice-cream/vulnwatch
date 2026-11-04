<?php

namespace GlpiPlugin\Vulnwatch\Matching;

/**
 * Propose des associations « logiciel GLPI → produit CPE » à partir des produits
 * effectivement cités par les CVE de la base locale.
 *
 * Statuts :
 *  - auto      : dictionnaire vérifié, ou nom ET éditeur concordants, sans autre candidat ;
 *  - proposed  : ressemblance (nom seul, inclusion, plusieurs candidats) → résultats « À vérifier » ;
 *  - validated / rejected : décision de l'administrateur, jamais écrasée par une analyse.
 */
final class Mapper
{
    /**
     * Correspondances vérifiées (nom normalisé GLPI → vendor:product NVD).
     * Les clés sont le résultat de Normalizer::softwareName().
     */
    public const DICTIONARY = [
        'mozilla firefox'              => ['mozilla', 'firefox'],
        'mozilla firefox esr'          => ['mozilla', 'firefox_esr'],
        'mozilla thunderbird'          => ['mozilla', 'thunderbird'],
        'google chrome'                => ['google', 'chrome'],
        'microsoft edge'               => ['microsoft', 'edge_chromium'],
        '7-zip'                        => ['7-zip', '7-zip'],
        'notepad++'                    => ['notepad-plus-plus', 'notepad++'],
        'vlc media player'             => ['videolan', 'vlc_media_player'],
        'putty release'                => ['putty', 'putty'],
        'putty'                        => ['putty', 'putty'],
        'winrar'                       => ['rarlab', 'winrar'],
        'winscp'                       => ['winscp', 'winscp'],
        'filezilla client'             => ['filezilla-project', 'filezilla_client'],
        'filezilla'                    => ['filezilla-project', 'filezilla_client'],
        'adobe acrobat reader dc'      => ['adobe', 'acrobat_reader_dc'],
        'adobe acrobat reader'         => ['adobe', 'acrobat_reader'],
        'keepass password safe'        => ['keepass', 'keepass'],
        'keepass'                      => ['keepass', 'keepass'],
        'libreoffice'                  => ['libreoffice', 'libreoffice'],
        'git'                          => ['git-scm', 'git'],
        'openssl'                      => ['openssl', 'openssl'],
        'openssh'                      => ['openbsd', 'openssh'],
        'openssh server'               => ['openbsd', 'openssh'],
        'openssh client'               => ['openbsd', 'openssh'],
        'zoom'                         => ['zoom', 'meeting_software'],
        'teamviewer'                   => ['teamviewer', 'teamviewer'],
        'anydesk'                      => ['anydesk', 'anydesk'],
        'wireshark'                    => ['wireshark', 'wireshark'],
        'python'                       => ['python', 'python'],
        'java runtime environment'     => ['oracle', 'jre'],
        'veeam backup replication'     => ['veeam', 'veeam_backup_&_replication'],
        'fortinet forticlient'         => ['fortinet', 'forticlient'],
        'forticlient'                  => ['fortinet', 'forticlient'],
        'apache http server'           => ['apache', 'http_server'],
        'nginx'                        => ['f5', 'nginx'],
        'php'                          => ['php', 'php'],
        'mysql server'                 => ['oracle', 'mysql'],
        'mariadb'                      => ['mariadb', 'mariadb'],
        'postgresql'                   => ['postgresql', 'postgresql'],
    ];

    /**
     * @param array<string, list<string>> $productsByToken  « firefox » → ["mozilla:firefox", …]
     * @return list<array{vendor:string,product:string,status:string,confidence:int,reason:string}>
     */
    public static function candidates(string $nameNorm, string $manufNorm, array $productsByToken, array $knownProducts): array
    {
        if ($nameNorm === '') {
            return [];
        }
        $out = [];
        $add = static function (string $vendor, string $product, string $status, int $conf, string $reason) use (&$out): void {
            $k = $vendor . ':' . $product;
            if (!isset($out[$k]) || $out[$k]['confidence'] < $conf) {
                $out[$k] = ['vendor' => $vendor, 'product' => $product, 'status' => $status, 'confidence' => $conf, 'reason' => $reason];
            }
        };

        // Paquets Linux : « openssh-server » ⇔ « openssh server » (le tiret est conservé pour « 7-zip »)
        $dashless = str_replace('-', ' ', $nameNorm);
        foreach (array_unique([$nameNorm, $dashless]) as $n) {
            if (isset(self::DICTIONARY[$n])) {
                [$v, $p] = self::DICTIONARY[$n];
                $add($v, $p, 'auto', 95, 'Dictionnaire vérifié du plugin');
                break;
            }
        }

        $nameTokens = Normalizer::tokens($nameNorm);
        $manufTokens = Normalizer::tokens($manufNorm);
        $tryNames = array_values(array_unique([$nameNorm, $dashless]));
        // « mozilla firefox » (éditeur « mozilla » ou vide) → produit « firefox » ; l'éditeur est vérifié ensuite
        if (count($nameTokens) > 1 && ($manufTokens === [] || $nameTokens[0] === $manufTokens[0])) {
            $tryNames[] = implode(' ', array_slice($nameTokens, 1));
        }

        foreach ($tryNames as $candidateName) {
            foreach ($productsByToken[$candidateName] ?? [] as $vp) {
                [$vendor, $product] = explode(':', $vp, 2);
                if (self::vendorMatches($vendor, $manufTokens, $nameTokens)) {
                    $add($vendor, $product, 'auto', 85, 'Nom et éditeur concordants avec le produit CPE');
                } else {
                    $add($vendor, $product, 'proposed', 50, $manufNorm === ''
                        ? 'Nom identique au produit CPE, éditeur absent de l\'inventaire'
                        : 'Nom identique au produit CPE mais éditeur différent (« ' . $manufNorm . ' » / « ' . $vendor . ' »)');
                }
            }
        }

        // Inclusion : tous les jetons du produit présents dans le nom, éditeur concordant
        foreach ($knownProducts as $vp => $productTokens) {
            [$vendor, $product] = explode(':', $vp, 2);
            if (isset($out[$vp]) || count($productTokens) === 0) {
                continue;
            }
            if (count(array_diff($productTokens, array_merge($nameTokens, Normalizer::tokens($dashless)))) === 0 && self::vendorMatches($vendor, $manufTokens, $nameTokens)
                && (count($productTokens) >= 2 || strlen($productTokens[0]) >= 5)) {
                $add($vendor, $product, 'proposed', 60, 'Produit CPE inclus dans le nom du logiciel, éditeur concordant');
            }
        }

        $list = array_values($out);
        // Plusieurs candidats automatiques non issus du dictionnaire : ambiguïté → proposés
        $autos = array_filter($list, static fn($c) => $c['status'] === 'auto');
        if (count($autos) > 1) {
            foreach ($list as &$c) {
                if ($c['status'] === 'auto' && $c['confidence'] < 95) {
                    $c['status'] = 'proposed';
                    $c['confidence'] = 55;
                    $c['reason'] .= ' — plusieurs produits possibles';
                }
            }
            unset($c);
        }
        return $list;
    }

    /** @param list<string> $manufTokens */
    private static function vendorMatches(string $vendor, array $manufTokens, array $nameTokens): bool
    {
        $v = Normalizer::cpeToken($vendor);
        if ($v === '') {
            return false;
        }
        $vTokens = Normalizer::tokens(str_replace('-', ' ', $v));
        $hay = array_merge($manufTokens, Normalizer::tokens(str_replace('-', ' ', implode(' ', $manufTokens))));
        if ($manufTokens !== [] && count(array_diff($vTokens, $hay)) === 0) {
            return true;
        }
        // L'éditeur peut figurer en tête du nom (« Mozilla Firefox ») quand la colonne éditeur est vide
        return $manufTokens === [] && $nameTokens !== [] && $nameTokens[0] === $vTokens[0];
    }
}
