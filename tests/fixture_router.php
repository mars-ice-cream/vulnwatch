<?php
// Serveur de jeux de test : php -S 127.0.0.2:8099 tests/fixture_router.php
$base = __DIR__ . '/fixtures';
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$mode = @file_get_contents('/tmp/vulnwatch_fixture_mode') ?: 'normal';
header('Cache-Control: no-store');
switch (true) {
    case $path === '/nvd' && isset($_GET['lastModStartDate']):
        // Mode incrémental : 3 CVE, une par page, pour tester la reprise
        $ids = ['CVE-2024-9680', 'CVE-2024-11477', 'CVE-2023-4863'];
        $i = (int) ($_GET['startIndex'] ?? 0);
        header('Content-Type: application/json');
        $vulns = isset($ids[$i]) ? json_decode(file_get_contents("$base/nvd/{$ids[$i]}.json"), true)['vulnerabilities'] : [];
        echo json_encode(['resultsPerPage' => count($vulns), 'startIndex' => $i, 'totalResults' => count($ids), 'vulnerabilities' => $vulns]);
        break;
    case $path === '/nvd':
        $id = preg_replace('/[^A-Z0-9-]/', '', strtoupper($_GET['cveId'] ?? ''));
        header('Content-Type: application/json');
        $f = "$base/nvd/$id.json";
        echo is_file($f) ? file_get_contents($f) : json_encode(['resultsPerPage' => 0, 'startIndex' => 0, 'totalResults' => 0, 'vulnerabilities' => []]);
        break;
    case $path === '/kev.json':
        header('Content-Type: application/json');
        readfile("$base/kev.json");
        break;
    case $path === '/feeds/certfr.xml':
        if ($mode === 'certfr_down') { http_response_code(503); echo 'Service Unavailable'; break; }
        header('Content-Type: application/rss+xml');
        readfile("$base/feeds/certfr.xml");
        break;
    case $path === '/feeds/vendor.atom':
        header('Content-Type: application/atom+xml');
        readfile("$base/feeds/vendor.atom");
        break;
    case $path === '/feeds/xxe.xml':
        header('Content-Type: application/xml');
        readfile("$base/feeds/xxe.xml");
        break;
    case $path === '/feeds/error':
        http_response_code(500);
        echo 'boom';
        break;
    case $path === '/feeds/redirect-internal':
        header('Location: http://127.0.0.1:8099/kev.json');
        http_response_code(302);
        break;
    case $path === '/feeds/big':
        header('Content-Type: application/xml');
        echo '<rss version="2.0"><channel><title>big</title>' . str_repeat('<item><title>x</title></item>', 200000) . '</channel></rss>';
        break;
    default:
        http_response_code(404);
}
