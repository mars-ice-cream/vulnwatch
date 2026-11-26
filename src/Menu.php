<?php

namespace GlpiPlugin\Vulnwatch;

use CommonGLPI;
use Session;

final class Menu extends Compat\PluginRightItem
{
    public static function getTypeName($nb = 0)
    {
        return __('Vulnérabilités', 'vulnwatch');
    }

    public static function getMenuName()
    {
        return self::getTypeName();
    }

    public static function getIcon()
    {
        return 'ti ti-shield-exclamation';
    }

    public static function url(string $page, array $params = []): string
    {
        global $CFG_GLPI;
        $url = $CFG_GLPI['root_doc'] . '/plugins/vulnwatch/front/' . $page;
        return $params === [] ? $url : $url . '?' . http_build_query($params);
    }

    public static function getMenuContent()
    {
        if (!Session::haveRight(self::$rightname, READ)) {
            return false;
        }
        $menu = [
            'title' => self::getMenuName(),
            'page'  => self::url('dashboard.php'),
            'icon'  => self::getIcon(),
            'options' => [],
        ];
        foreach (self::pages() as $key => [$title, $page, $icon]) {
            $menu['options'][$key] = ['title' => $title, 'page' => self::url($page), 'icon' => $icon];
            if (in_array($key, ['feed', 'target'], true)) {
                $menu['options'][$key]['links'] = ['search' => self::url($page)];
                if (Session::haveRight('plugin_vulnwatch_config', UPDATE)) {
                    $menu['options'][$key]['links']['add'] = self::url($key . '.form.php');
                }
            }
        }
        return $menu;
    }

    /** Pages du plugin visibles avec les droits de la session. @return array<string,array{0:string,1:string,2:string}> */
    public static function pages(): array
    {
        $links = [
            'dashboard' => [__('Tableau de bord', 'vulnwatch'), 'dashboard.php', 'ti ti-layout-dashboard'],
            'cve'       => [__('Par CVE', 'vulnwatch'), 'cve.php', 'ti ti-bug'],
            'software'  => [__('Par logiciel', 'vulnwatch'), 'software.php', 'ti ti-apps'],
            'review'    => [__('Veille à vérifier', 'vulnwatch'), 'review.php', 'ti ti-eye-check'],
            'mapping'   => [__('Associations', 'vulnwatch'), 'mapping.php', 'ti ti-link'],
        ];
        if (Session::haveRight('plugin_vulnwatch_config', READ)) {
            $links['feed']   = [__('Flux de veille', 'vulnwatch'), 'feed.php', 'ti ti-rss'];
            $links['target'] = [__('Versions cibles', 'vulnwatch'), 'target.php', 'ti ti-target'];
            $links['config'] = [__('Configuration', 'vulnwatch'), 'config.php', 'ti ti-settings'];
        }
        return $links;
    }
}
