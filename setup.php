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
// GLPI 11.0.x testé ; GLPI 12 déclaré mais non testé (borne max exclusive).
define('PLUGIN_VULNWATCH_MIN_GLPI', '11.0.0');
define('PLUGIN_VULNWATCH_MAX_GLPI', '12.99.99');

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
