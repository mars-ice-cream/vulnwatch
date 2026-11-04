<?php

namespace GlpiPlugin\Vulnwatch;

/** Petits composants d'affichage partagés (toutes les valeurs sont échappées). */
final class Ui
{
    public const FINDING_LABELS = [
        'established'   => ['Correspondance établie', 'bg-danger'],
        'to_check'      => ['À vérifier', 'bg-warning text-dark'],
        'not_evaluated' => ['Non évalué', 'bg-secondary'],
        'not_affected'  => ['Non affecté', 'bg-success'],
        'rejected'      => ['Association rejetée', 'bg-light text-dark'],
    ];

    public const ITEM_STATE_LABELS = [
        'active'       => ['Actif', 'bg-danger'],
        'fixed'        => ['Corrigé', 'bg-success'],
        'unverified'   => ['Correction non confirmée', 'bg-warning text-dark'],
        'closed'       => ['Clos', 'bg-light text-dark'],
        'out_of_scope' => ['Hors périmètre', 'bg-light text-dark'],
    ];

    public static function e(mixed $v): string
    {
        return htmlescape((string) ($v ?? ''));
    }

    public static function badge(string $label, string $class): string
    {
        if (!str_contains($class, 'text-')) {
            $class .= ' text-white';
        }
        return "<span class='badge " . self::e($class) . "'>" . self::e($label) . '</span>';
    }

    public static function findingBadge(string $status): string
    {
        [$l, $c] = self::FINDING_LABELS[$status] ?? [$status, 'bg-secondary'];
        return self::badge($l, $c);
    }

    public static function itemStateBadge(string $state, bool $regression = false): string
    {
        [$l, $c] = self::ITEM_STATE_LABELS[$state] ?? [$state, 'bg-secondary'];
        return self::badge($l, $c) . ($regression ? ' ' . self::badge('Régression', 'bg-dark') : '');
    }

    public static function syncBadge(string $status): string
    {
        return match ($status) {
            'ok'    => self::badge('OK', 'bg-success'),
            'error' => self::badge('Erreur', 'bg-danger'),
            default => self::badge('Jamais synchronisé', 'bg-secondary'),
        };
    }

    public static function priorityBadge(array $p): string
    {
        $cls = ['P1' => 'bg-danger', 'P2' => 'bg-orange', 'P3' => 'bg-warning text-dark', 'P4' => 'bg-secondary'][$p['level']] ?? 'bg-secondary';
        $title = implode("\n", array_map(static fn($f) => $f[0] . ' : +' . $f[1], $p['factors']));
        $cls .= str_contains($cls, 'text-') ? '' : ' text-white';
        return "<span class='badge " . $cls . "' title='" . self::e($title) . "'>" . self::e($p['level'] . ' (' . $p['score'] . ')') . '</span>';
    }

    /** Critères de priorité en version courte (le détail est au survol du badge). */
    public static function priorityFactors(array $p): string
    {
        return "<div class='small text-muted'>" . self::e(implode(' · ', array_map(static fn($f) => ($f[2] ?? $f[0]) . ' +' . $f[1], $p['factors']))) . '</div>';
    }

    public static function confidence(int $c): string
    {
        $cls = $c >= 80 ? 'text-success' : ($c >= 50 ? 'text-warning' : 'text-muted');
        return "<span class='" . $cls . "' title='Fiabilité de la détection (indépendante de la gravité)'>" . $c . ' %</span>';
    }

    public static function cveLink(string $cveId, int $pk): string
    {
        return "<a href='" . self::e(Menu::url('cve.php', ['id' => $pk])) . "'>" . self::e($cveId) . '</a>';
    }

    public static function itemLink(string $itemtype, int $id): string
    {
        $item = getItemForItemtype($itemtype);
        if (!$item || !$item->getFromDB($id)) {
            return self::e($itemtype . ' #' . $id);
        }
        return "<a href='" . self::e($item->getLinkURL()) . "'>" . self::e($item->fields['name'] ?: ($itemtype . ' #' . $id)) . '</a>';
    }

    public static function reasons(?string $json): string
    {
        $list = json_decode((string) $json, true) ?: [];
        if ($list === []) {
            return '';
        }
        return '<ul class="mb-0 small">' . implode('', array_map(static fn($r) => '<li>' . self::e($r) . '</li>', $list)) . '</ul>';
    }

    public static function staleBadge(?string $lastInventory): string
    {
        if ($lastInventory === null || $lastInventory === '') {
            return self::badge('Jamais inventorié par agent', 'bg-warning text-dark');
        }
        return Inventory::isStale($lastInventory)
            ? self::badge('Inventaire ancien : ' . substr($lastInventory, 0, 10), 'bg-warning text-dark')
            : "<span class='small text-muted'>" . self::e(substr($lastInventory, 0, 16)) . '</span>';
    }

    public static function card(string $title, string $value, string $sub = '', string $class = ''): string
    {
        return "<div class='col-sm-6 col-lg-3 mb-3'><div class='card " . self::e($class) . "'><div class='card-body'>"
            . "<div class='subheader'>" . self::e($title) . "</div><div class='h1 mb-1'>" . self::e($value) . '</div>'
            . ($sub !== '' ? "<div class='small text-muted'>" . $sub . '</div>' : '') . '</div></div></div>';
    }

    /** Critère SQL de restriction aux entités actives de la session, sur un alias de table. */
    public static function entityCriteria(string $tableOrAlias, string $field = 'entities_id'): array
    {
        return getEntitiesRestrictCriteria($tableOrAlias, $field, '', false);
    }

    public static function header(string $title, string $option): void
    {
        \Html::header($title, '', 'tools', Menu::class, $option);
    }
}
