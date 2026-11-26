<?php
// Charge chaque classe du plugin sur le cœur GLPI ciblé : php tests/load_classes.php /chemin/glpi
require __DIR__ . '/bootstrap_glpi.php';
$base = dirname(__DIR__) . '/src';
$fail = 0;
$n = 0;
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base)) as $f) {
    if ($f->getExtension() !== 'php') {
        continue;
    }
    $class = 'GlpiPlugin\\Vulnwatch\\' . str_replace(['/', '.php'], ['\\', ''], substr($f->getPathname(), strlen($base) + 1));
    try {
        $ok = class_exists($class) || interface_exists($class);
        $n++;
        if (!$ok) {
            $fail++;
            echo "FAIL $class (introuvable)\n";
        }
    } catch (\Throwable $e) {
        $fail++;
        echo "FAIL $class : " . $e->getMessage() . "\n";
    }
}
echo sprintf("GLPI %s : %d classes chargées, %d échecs\n", GLPI_VERSION, $n, $fail);
exit($fail ? 1 : 0);
