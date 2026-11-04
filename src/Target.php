<?php

namespace GlpiPlugin\Vulnwatch;

use CommonDBTM;
use GlpiPlugin\Vulnwatch\Matching\Normalizer;
use GlpiPlugin\Vulnwatch\Matching\VersionComparator;

/**
 * Version cible approuvée et fin de support, définies par l'administrateur pour une entité.
 * Distinct de la CVE : « en dessous de la cible » ou « fin de support » ne signifie pas « vulnérable ».
 */
final class Target extends Compat\ConfigRightDbtm
{

    public static function getTypeName($nb = 0)
    {
        return _n('Version cible', 'Versions cibles', $nb, 'vulnwatch');
    }

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_vulnwatch_targets';
    }

    public static function getIcon()
    {
        return 'ti ti-target';
    }

    // Droit « configuration » : UPDATE suffit pour créer, modifier ou supprimer
    public static function canCreate(): bool
    {
        return \Session::haveRight(static::$rightname, UPDATE);
    }

    public static function canPurge(): bool
    {
        return \Session::haveRight(static::$rightname, UPDATE);
    }

    public static function canDelete(): bool
    {
        return \Session::haveRight(static::$rightname, UPDATE);
    }

    public function maybeRecursive()
    {
        return true;
    }

    public function isEntityAssign()
    {
        return true;
    }

    public function prepareInputForAdd($input)
    {
        return $this->clean($input, true);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->clean($input, false);
    }

    private function clean(array $input, bool $isNew): array|false
    {
        if ($isNew || isset($input['software_name'])) {
            $input['software_name'] = trim((string) ($input['software_name'] ?? ''));
            if ($input['software_name'] === '') {
                \Session::addMessageAfterRedirect(__('Le nom du logiciel est obligatoire.', 'vulnwatch'), false, ERROR);
                return false;
            }
            $input['name_norm'] = Normalizer::softwareName($input['software_name']);
        }
        foreach (['target_version', 'eol_branch', 'eol_date'] as $f) {
            if (isset($input[$f]) && trim((string) $input[$f]) === '') {
                $input[$f] = 'NULL';
            }
        }
        $input['users_id'] = (int) \Session::getLoginUserID();
        return $input;
    }

    /** Règle applicable à un logiciel pour une entité (règle de l'entité, sinon d'un parent récursif). */
    public static function findFor(string $softwareName, int $entityId): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $norm = Normalizer::softwareName($softwareName);
        $ancestors = array_values(getAncestorsOf('glpi_entities', $entityId));
        $best = null;
        foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['name_norm' => $norm, 'OR' => [
            ['entities_id' => $entityId],
            ['entities_id' => $ancestors ?: [-1], 'is_recursive' => 1],
        ]]]) as $r) {
            // La règle la plus proche de l'entité l'emporte
            if ($best === null || (int) $r['entities_id'] === $entityId || ((int) $best['entities_id'] !== $entityId && (int) $r['entities_id'] > (int) $best['entities_id'])) {
                $best = $r;
            }
        }
        return $best;
    }

    /**
     * @return array{below_target:?bool, eol:?bool, target:?string, eol_text:?string, source:string}
     */
    public static function assess(string $softwareName, string $version, int $entityId): array
    {
        $t = self::findFor($softwareName, $entityId);
        if ($t === null) {
            return ['below_target' => null, 'eol' => null, 'target' => null, 'eol_text' => null, 'source' => ''];
        }
        $below = null;
        if (!empty($t['target_version'])) {
            $c = VersionComparator::compare($version, $t['target_version']);
            $below = $c === null ? null : $c < 0;
        }
        $eol = null;
        $eolText = null;
        if (!empty($t['eol_branch'])) {
            $c = VersionComparator::compare($version, $t['eol_branch']);
            $eol = $c === null ? null : $c < 0;
            $eolText = 'branches < ' . $t['eol_branch'];
        }
        if (!empty($t['eol_date']) && strtotime($t['eol_date']) <= time() && empty($t['eol_branch'])) {
            $eol = true;
            $eolText = 'fin de support le ' . $t['eol_date'];
        }
        return ['below_target' => $below, 'eol' => $eol, 'target' => $t['target_version'] ?: null, 'eol_text' => $eolText, 'source' => (string) $t['source']];
    }

    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();
        $tab[] = ['id' => 2, 'table' => self::getTable(), 'field' => 'software_name', 'name' => __('Logiciel', 'vulnwatch'), 'datatype' => 'itemlink'];
        $tab[] = ['id' => 3, 'table' => self::getTable(), 'field' => 'target_version', 'name' => __('Version cible', 'vulnwatch'), 'datatype' => 'string'];
        $tab[] = ['id' => 4, 'table' => self::getTable(), 'field' => 'eol_branch', 'name' => __('Fin de support : branches antérieures à', 'vulnwatch'), 'datatype' => 'string'];
        $tab[] = ['id' => 5, 'table' => self::getTable(), 'field' => 'eol_date', 'name' => __('Date de fin de support', 'vulnwatch'), 'datatype' => 'date'];
        $tab[] = ['id' => 6, 'table' => self::getTable(), 'field' => 'source', 'name' => __('Source', 'vulnwatch'), 'datatype' => 'string'];
        $tab[] = ['id' => 80, 'table' => 'glpi_entities', 'field' => 'completename', 'name' => \Entity::getTypeName(1), 'datatype' => 'dropdown'];
        return $tab;
    }

    public function defineTabs($options = [])
    {
        $ong = [];
        $this->addDefaultFormTab($ong);
        $this->addStandardTab(\Log::class, $ong, $options);
        return $ong;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);
        $f = $this->fields;
        $h = static fn($v) => htmlescape((string) ($v ?? ''));
        echo "<tr class='tab_bg_1'><td>" . __('Logiciel (nom tel qu\'inventorié)', 'vulnwatch') . " *</td><td><input class='form-control' name='software_name' required value='{$h($f['software_name'] ?? '')}'></td>";
        echo '<td>' . __('Version cible approuvée', 'vulnwatch') . "</td><td><input class='form-control' name='target_version' value='{$h($f['target_version'] ?? '')}'></td></tr>";
        echo "<tr class='tab_bg_1'><td>" . __('Fin de support : branches antérieures à', 'vulnwatch') . "</td><td><input class='form-control' name='eol_branch' value='{$h($f['eol_branch'] ?? '')}'></td>";
        echo '<td>' . __('Date de fin de support du produit', 'vulnwatch') . "</td><td><input type='date' class='form-control' name='eol_date' value='{$h($f['eol_date'] ?? '')}'></td></tr>";
        echo "<tr class='tab_bg_1'><td>" . __('Source (avis éditeur, politique interne)', 'vulnwatch') . "</td><td colspan='3'><input class='form-control' name='source' value='{$h($f['source'] ?? '')}'></td></tr>";
        echo "<tr class='tab_bg_1'><td>" . __('Commentaire') . "</td><td colspan='3'><textarea class='form-control' name='comment'>{$h($f['comment'] ?? '')}</textarea></td></tr>";
        $this->showFormButtons($options);
        return true;
    }
}
