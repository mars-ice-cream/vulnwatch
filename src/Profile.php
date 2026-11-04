<?php

namespace GlpiPlugin\Vulnwatch;

use CommonGLPI;
use Html;
use ProfileRight;
use Session;

/**
 * Droits du plugin, affichés dans un onglet de la fiche Profil (mécanisme natif).
 *
 * plugin_vulnwatch        : READ (consulter), UPDATE (valider/rejeter associations, traiter la veille,
 *                           contexte d'actif), CREATE (créer/compléter des tickets de campagne)
 * plugin_vulnwatch_config : READ, UPDATE (flux, versions cibles, paramètres, automatisation)
 */
final class Profile extends \Profile
{
    public static $rightname = 'profile';

    public const RIGHTS = ['plugin_vulnwatch', 'plugin_vulnwatch_config'];

    public static function getAllRights(): array
    {
        return [
            [
                'itemtype' => Menu::class,
                'label'    => __('Vulnérabilités (consultation, décisions, tickets)', 'vulnwatch'),
                'field'    => 'plugin_vulnwatch',
                'rights'   => [READ => __('Read'), UPDATE => __('Update'), CREATE => __('Create')],
            ],
            [
                'itemtype' => Menu::class,
                'label'    => __('Vulnérabilités – configuration (flux, cibles, paramètres)', 'vulnwatch'),
                'field'    => 'plugin_vulnwatch_config',
                'rights'   => [READ => __('Read'), UPDATE => __('Update')],
            ],
        ];
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof \Profile && $item->getField('interface') === 'central') {
            return self::createTabEntry(__('Vulnérabilités', 'vulnwatch'), 0, null, 'ti ti-shield-exclamation');
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!$item instanceof \Profile) {
            return false;
        }
        $canedit = Session::haveRightsOr('profile', [CREATE, UPDATE, PURGE]);
        echo "<div class='spaced'>";
        if ($canedit) {
            echo "<form method='post' action='" . htmlescape(\Profile::getFormURL()) . "'>";
        }
        $item->displayRightsChoiceMatrix(self::getAllRights(), [
            'canedit'       => $canedit,
            'default_class' => 'tab_bg_2',
            'title'         => __('VulnWatch', 'vulnwatch'),
        ]);
        if ($canedit) {
            echo "<div class='center'>";
            echo Html::hidden('id', ['value' => $item->getID()]);
            echo Html::submit(_sx('button', 'Save'), ['name' => 'update', 'class' => 'btn btn-primary']);
            echo '</div>';
            Html::closeForm();
        }
        echo '</div>';
        return true;
    }

    public static function installRights(): void
    {
        /** @var \DBmysql $DB */
        global $DB;
        $existing = [];
        foreach ($DB->request(['SELECT' => ['name'], 'DISTINCT' => true, 'FROM' => ProfileRight::getTable(), 'WHERE' => ['name' => self::RIGHTS]]) as $r) {
            $existing[] = $r['name'];
        }
        $missing = array_values(array_diff(self::RIGHTS, $existing));
        if ($missing !== []) {
            ProfileRight::addProfileRights($missing);
            // Profils ayant tous les droits sur la configuration GLPI (super-admin) : accès complet
            foreach ($DB->request(['SELECT' => ['profiles_id'], 'FROM' => ProfileRight::getTable(), 'WHERE' => ['name' => 'config', 'rights' => ['&', UPDATE]]]) as $p) {
                foreach ($missing as $right) {
                    $value = $right === 'plugin_vulnwatch' ? (READ | UPDATE | CREATE) : (READ | UPDATE);
                    $DB->update(ProfileRight::getTable(), ['rights' => $value], ['profiles_id' => $p['profiles_id'], 'name' => $right]);
                }
            }
        }
        // Rafraîchir la session courante si elle existe
        if (isset($_SESSION['glpiactiveprofile']['id'])) {
            foreach ($DB->request(['FROM' => ProfileRight::getTable(), 'WHERE' => ['profiles_id' => $_SESSION['glpiactiveprofile']['id'], 'name' => self::RIGHTS]]) as $r) {
                $_SESSION['glpiactiveprofile'][$r['name']] = (int) $r['rights'];
            }
        }
    }

    public static function uninstallRights(): void
    {
        ProfileRight::deleteProfileRights(self::RIGHTS);
        foreach (self::RIGHTS as $right) {
            unset($_SESSION['glpiactiveprofile'][$right]);
        }
    }
}
