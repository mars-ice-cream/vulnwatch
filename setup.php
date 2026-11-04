<?php

/**
 * VulnWatch - Veille vulnérabilités pour GLPI
 *
 * Croise l'inventaire GLPI existant avec des sources de vulnérabilités
 * (NVD, CISA KEV, flux RSS/Atom configurables) et suit les corrections.
 *
 * @license GPL-3.0-or-later
 */

use Glpi\Plugin\Hooks;
use GlpiPlugin\Vulnwatch\AssetTab;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Profile as VulnwatchProfile;

define('PLUGIN_VULNWATCH_VERSION', '1.0.0');
// Testé sur GLPI 11.0.9 et 12.0.1 (classes de base par version dans compat/).
define('PLUGIN_VULNWATCH_MIN_GLPI', '11.0.0');
define('PLUGIN_VULNWATCH_MAX_GLPI', '12.99.99');

/**
 * Compatibilité GLPI 11 / 12 dans un seul paquet : GLPI 12 type les propriétés héritées
 * ($rightname, $dohistory…) et PHP impose une déclaration identique dans les classes filles.
 * Les classes de base GlpiPlugin\Vulnwatch\Compat\* sont donc chargées depuis compat/glpi11 ou compat/glpi12.
 */
function plugin_vulnwatch_register_compat_autoload(): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;
    $dir = __DIR__ . '/compat/' . (version_compare(plugin_vulnwatch_glpi_version(), '12.0.0-dev', '>=') ? 'glpi12' : 'glpi11');
    spl_autoload_register(static function (string $class) use ($dir): void {
        $prefix = 'GlpiPlugin\\Vulnwatch\\Compat\\';
        if (str_starts_with($class, $prefix)) {
            $file = $dir . '/' . substr($class, strlen($prefix)) . '.php';
            if (is_file($file)) {
                require_once $file;
            }
        }
    });
}

function plugin_vulnwatch_glpi_version(): string
{
    return defined('GLPI_VERSION') ? GLPI_VERSION : '11.0.0';
}

plugin_vulnwatch_register_compat_autoload();

function plugin_version_vulnwatch(): array
{
    return [
        'name'         => 'VulnWatch – Veille vulnérabilités',
        'version'      => PLUGIN_VULNWATCH_VERSION,
        'author'       => 'Gerome Le Duff',
        'license'      => 'GPL-3.0-or-later',
        'homepage'     => '',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_VULNWATCH_MIN_GLPI,
                'max' => PLUGIN_VULNWATCH_MAX_GLPI,
            ],
            'php' => [
                'min'  => '8.2',
                'exts' => [
                    'curl'   => ['required' => true],
                    'dom'    => ['required' => true],
                    'libxml' => ['required' => true],
                    'json'   => ['required' => true],
                ],
            ],
        ],
    ];
}

function plugin_vulnwatch_check_prerequisites(): bool
{
    return true;
}

function plugin_vulnwatch_check_config($verbose = false): bool
{
    return true;
}

function plugin_init_vulnwatch(): void
{
    global $PLUGIN_HOOKS;

    $plugin = new Plugin();
    if (!$plugin->isActivated('vulnwatch')) {
        return;
    }

    Plugin::registerClass(VulnwatchProfile::class, ['addtabon' => ['Profile']]);
    Plugin::registerClass(AssetTab::class, ['addtabon' => AssetTab::SUPPORTED_ITEMTYPES]);

    if (Session::haveRight(Menu::$rightname, READ)) {
        $PLUGIN_HOOKS[Hooks::MENU_TOADD]['vulnwatch'] = ['tools' => Menu::class];
    }
    foreach (AssetTab::SUPPORTED_ITEMTYPES as $itemtype) {
        $PLUGIN_HOOKS[Hooks::ITEM_PURGE]['vulnwatch'][$itemtype] = 'plugin_vulnwatch_item_purge';
    }
    if (Session::haveRight('plugin_vulnwatch_config', UPDATE)) {
        $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['vulnwatch'] = 'front/config.php';
    }
}
