<?php

/**
 * Tests unitaires sans GLPI (logique pure) : php tests/unit.php
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'GlpiPlugin\\Vulnwatch\\';
    if (str_starts_with($class, $prefix)) {
        $f = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($f)) {
            require $f;
        }
    }
});

use GlpiPlugin\Vulnwatch\Http\SafeHttpClient;
use GlpiPlugin\Vulnwatch\Matching\Evaluator;
use GlpiPlugin\Vulnwatch\Matching\Mapper;
use GlpiPlugin\Vulnwatch\Matching\Normalizer;
use GlpiPlugin\Vulnwatch\Matching\VersionComparator as V;
use GlpiPlugin\Vulnwatch\Source\FeedParser;
use GlpiPlugin\Vulnwatch\Source\NvdConnector;

$pass = $fail = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    $ok ? $pass++ : $fail++;
    echo ($ok ? "  ok   " : "  FAIL ") . $name . ($ok || $detail === '' ? '' : " — $detail") . "\n";
}

echo "Comparaison de versions\n";
foreach ([
    ['1.0', '1.0.0', 0], ['1.0.1', '1.0', 1], ['130.0', '131.0.2', -1], ['131.0.3', '131.0.2', 1], ['2.0rc1', '2.0', -1],
    ['2.0beta', '2.0alpha', 1], ['24.07', '24.7', 0], ['23.01', '24.07', -1], ['v1.2', '1.2', 0], ['10.0.19045.4529', '10.0.19045.3803', 1],
    ['116.0.5845.187', '116.0.5845.96', 1], ['9.6p1', '9.8', -1], ['1.2.3+build5', '1.2.3', 0],
] as [$a, $b, $exp]) {
    check("generic $a <=> $b = $exp", V::compare($a, $b) === $exp, var_export(V::compare($a, $b), true));
}
foreach ([['1:1.0-1', '2.0-1', 1], ['1.0~rc1-1', '1.0-1', -1], ['2.30-1ubuntu1', '2.30-1', 1], ['1.2.3-1', '1.2.3-10', -1], ['0:9.6p1-3', '9.6p1-3', 0]] as [$a, $b, $exp]) {
    check("dpkg $a <=> $b = $exp", V::compare($a, $b, 'dpkg') === $exp, var_export(V::compare($a, $b, 'dpkg'), true));
}
foreach ([['1.1.1k-12.el8', '1.1.1k-9.el8', 1], ['1.0~rc1', '1.0', -1], ['2.10', '2.9', 1], ['1.0a', '1.0', 1]] as [$a, $b, $exp]) {
    check("rpm $a <=> $b = $exp", V::compare($a, $b, 'rpm') === $exp, var_export(V::compare($a, $b, 'rpm'), true));
}
check('version vide non comparable', V::compare('', '1.0') === null);
check('version texte non comparable', V::compare('latest', '1.0') === null);
check('paquet Ubuntu détecté', V::looksLikeDistroPackage('1:9.6p1-3ubuntu13.5'));
check('paquet RHEL détecté', V::looksLikeDistroPackage('1.1.1k-12.el8_9'));
check('version Windows non détectée comme paquet', !V::looksLikeDistroPackage('131.0.2'));
check('partie amont Ubuntu', V::upstreamPart('1:9.6p1-3ubuntu13.5') === '9.6p1', V::upstreamPart('1:9.6p1-3ubuntu13.5'));

echo "Normalisation\n";
check('Firefox x64 fr', Normalizer::softwareName('Mozilla Firefox (x64 fr)') === 'mozilla firefox', Normalizer::softwareName('Mozilla Firefox (x64 fr)'));
check('7-Zip 23.01 (x64)', Normalizer::softwareName('7-Zip 23.01 (x64)') === '7-zip', Normalizer::softwareName('7-Zip 23.01 (x64)'));
check('Notepad++ (64-bit x64)', Normalizer::softwareName('Notepad++ (64-bit x64)') === 'notepad++', Normalizer::softwareName('Notepad++ (64-bit x64)'));
check('Éditeur Mozilla Corporation', Normalizer::manufacturer('Mozilla Corporation') === 'mozilla');
check('Éditeur Igor Pavlov', Normalizer::manufacturer('Igor Pavlov') === 'igor pavlov');
check('Produit CPE acrobat_reader_dc', Normalizer::cpeToken('acrobat_reader_dc') === 'acrobat reader dc');

echo "Associations\n";
$products = ['chrome' => ['google:chrome'], 'firefox' => ['mozilla:firefox'], 'php' => ['php:php']];
$known = ['google:chrome' => ['chrome'], 'mozilla:firefox' => ['firefox'], 'php:php' => ['php']];
$c = Mapper::candidates('mozilla firefox', 'mozilla', $products, $known);
check('Firefox : dictionnaire auto 95', $c[0]['status'] === 'auto' && $c[0]['confidence'] === 95 && $c[0]['product'] === 'firefox');
$c = Mapper::candidates('chrome', 'acme labs', $products, $known);
check('Chrome d\'un autre éditeur : proposé, pas auto', count($c) === 1 && $c[0]['status'] === 'proposed', json_encode($c));
$c = Mapper::candidates('google chrome', 'google', $products, $known);
check('Google Chrome : auto', $c !== [] && $c[0]['status'] === 'auto');
$c = Mapper::candidates('outil interne', 'ma societe', $products, $known);
check('Logiciel inconnu : aucun candidat', $c === []);
$c = Mapper::candidates('php', 'the php group', $products, $known);
check('PHP Group : auto par nom + éditeur', $c !== [] && $c[0]['status'] === 'auto', json_encode($c));

echo "Évaluation\n";
$crit = ['vendor' => 'mozilla', 'product' => 'firefox', 'criteria' => 'cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*', 'cpe_version' => '*', 'cpe_update' => '*', 'target_sw' => '*',
    'version_start_including' => null, 'version_start_excluding' => null, 'version_end_including' => null, 'version_end_excluding' => '131.0.2', 'conditions' => null];
$auto = ['status' => 'auto', 'confidence' => 95];
$r = Evaluator::evaluate($crit, '130.0', $auto);
check('version affectée → établie', $r['status'] === 'established' && $r['fixed_version'] === '131.0.2', json_encode($r));
$r = Evaluator::evaluate($crit, '131.0.2', $auto);
check('borne exclusive : 131.0.2 non affectée', $r['status'] === 'not_affected');
$r = Evaluator::evaluate($crit, '', $auto);
check('version inconnue → non évalué', $r['status'] === 'not_evaluated');
$r = Evaluator::evaluate($crit, '130.0', ['status' => 'proposed', 'confidence' => 50]);
check('association ambiguë → à vérifier', $r['status'] === 'to_check' && $r['confidence'] <= 50);
$r = Evaluator::evaluate(['version_end_including' => '8.5.6', 'version_end_excluding' => null] + $crit, '8.5.6', $auto);
check('borne inclusive : 8.5.6 affectée', $r['status'] === 'established');
$r = Evaluator::evaluate(['version_start_including' => '128.0', 'version_end_excluding' => '128.3.1'] + $crit, '127.9', $auto);
check('sous la borne basse inclusive : non affectée', $r['status'] === 'not_affected');
$r = Evaluator::evaluate(['conditions' => 'avec l\'un de : microsoft:windows'] + $crit, '130.0', $auto);
check('condition AND non vérifiable → à vérifier', $r['status'] === 'to_check', json_encode($r));
$r = Evaluator::evaluate(['version_start_including' => '8.5', 'version_end_excluding' => '9.8', 'vendor' => 'openbsd', 'product' => 'openssh'] + $crit, '1:9.6p1-3ubuntu13.5', $auto);
check('paquet Ubuntu dans la plage amont → à vérifier (rétroportage)', $r['status'] === 'to_check', json_encode($r));
$r = Evaluator::evaluate(['version_end_excluding' => null, 'cpe_version' => '*'] + $crit, '130.0', $auto);
check('critère sans borne → à vérifier', $r['status'] === 'to_check');
$r = Evaluator::evaluate(['target_sw' => 'windows'] + $crit, '130.0', $auto, ['os_families' => ['linux']]);
check('plateforme cible absente → non affectée', $r['status'] === 'not_affected');
$r = Evaluator::evaluate(['target_sw' => 'windows'] + $crit, '130.0', $auto, ['os_families' => ['windows']]);
check('plateforme cible vérifiée → établie', $r['status'] === 'established');
$r = Evaluator::evaluate(['target_sw' => 'windows'] + $crit, '130.0', $auto, ['os_families' => ['unknown']]);
check('plateforme inconnue → à vérifier', $r['status'] === 'to_check');

$r = Evaluator::evaluate(['target_hw' => 'x86'] + $crit, '130.0', ['status' => 'validated', 'confidence' => 100], ['arch' => 'arm64']);
check('matériel cible non vérifiable → à vérifier', $r['status'] === 'to_check', json_encode($r));

echo "NVD : critères et conditions\n";
$nvd = json_decode(file_get_contents(__DIR__ . '/fixtures/nvd/CVE-2024-4577.json'), true)['vulnerabilities'][0]['cve'];
$cr = NvdConnector::extractCriteria($nvd['configurations']);
check('PHP sur Windows : 2 critères vulnérables avec condition', count($cr) === 2 && str_contains((string) $cr[0]['conditions'], 'microsoft:windows'), json_encode($cr));
[$score, $ver] = NvdConnector::pickCvss($nvd['metrics']);
check('CVSS 3.1 retenu', $score === 9.8 && $ver === '3.1');

echo "Flux RSS / Atom\n";
$p = FeedParser::parse(file_get_contents(__DIR__ . '/fixtures/feeds/certfr.xml'));
check('RSS 2.0 : 6 articles bruts', $p['format'] === 'rss2' && count($p['items']) === 6);
check('CVE extraite d\'un lien HTML', in_array('CVE-2024-9680', $p['items'][0]['cves'], true));
check('CVE en minuscules normalisée', $p['items'][1]['cves'] === ['CVE-2024-11477']);
check('article sans CVE', $p['items'][2]['cves'] === []);
check('deux CVE dans un article', count($p['items'][4]['cves']) === 2);
check('script supprimé du résumé', !str_contains($p['items'][0]['summary'], 'alert'));
check('lien javascript: refusé', $p['items'][5]['link'] === '');
$p = FeedParser::parse(file_get_contents(__DIR__ . '/fixtures/feeds/vendor.atom'));
check('Atom : 2 entrées, CVE dans content HTML', $p['format'] === 'atom' && $p['items'][1]['cves'] === ['CVE-2023-4863']);
try {
    FeedParser::parse(file_get_contents(__DIR__ . '/fixtures/feeds/xxe.xml'));
    check('XXE refusé', false);
} catch (InvalidArgumentException $e) {
    check('XXE refusé', str_contains($e->getMessage(), 'XXE'));
}

echo "SSRF : adresses\n";
foreach (['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '::1', 'fe80::1', 'fd00::1', '::ffff:10.0.0.1', '0.0.0.0'] as $ip) {
    check("$ip refusée", !SafeHttpClient::isPublicIp($ip));
}
foreach (['8.8.8.8', '2a00:1450:4007:80e::200e'] as $ip) {
    check("$ip acceptée", SafeHttpClient::isPublicIp($ip));
}
check('redirection relative résolue', SafeHttpClient::resolveRelative('https://a.example/x/y.xml', '/z') === 'https://a.example/z');

echo "\n$pass réussis, $fail échecs\n";
exit($fail === 0 ? 0 : 1);
