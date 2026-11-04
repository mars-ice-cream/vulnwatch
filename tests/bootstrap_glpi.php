<?php
// Démarre GLPI 11 en CLI pour les tests d'intégration : php tests/xxx.php /chemin/vers/glpi
ob_start(); // aucune sortie avant la fin : la session PHP (Session::init) exige des en-têtes non envoyés
$glpiRoot = $argv[1] ?? getenv('GLPI_ROOT') ?: '/var/www/glpi';
chdir($glpiRoot);
require_once $glpiRoot . '/vendor/autoload.php';
$kernel = new \Glpi\Kernel\Kernel('production');
$kernel->boot();
$app = new \Glpi\Console\Application($kernel); // déclenche le chargement config/DB/plugins comme bin/console
// La session PHP doit démarrer avant toute sortie en CLI
ini_set('session.use_cookies', '0');
ini_set('session.cache_limiter', '');
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
