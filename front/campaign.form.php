<?php

use GlpiPlugin\Vulnwatch\Campaign;
use GlpiPlugin\Vulnwatch\Menu;

Session::checkRight(Menu::$rightname, CREATE);
Session::checkRight('ticket', CREATE);

if (isset($_POST['add_to_campaign'])) {
    $ids = array_map('intval', (array) ($_POST['finding_items'] ?? []));
    if ($ids === []) {
        Session::addMessageAfterRedirect(__('Sélectionnez au moins une alerte.', 'vulnwatch'), false, WARNING);
    } else {
        $r = Campaign::addFindingItems($ids, false);
        $links = implode(', ', array_map(static fn($t) => '<a href="' . htmlescape(Ticket::getFormURLWithID($t)) . '">#' . (int) $t . '</a>', $r['tickets']));
        Session::addMessageAfterRedirect(sprintf(
            __('%1$d ticket(s) créé(s), %2$d complété(s), %3$d alerte(s) rattachée(s), %4$d déjà rattachée(s) ou hors périmètre. Tickets : %5$s', 'vulnwatch'),
            $r['tickets_created'], $r['tickets_updated'], $r['items_added'], $r['skipped'], $links ?: '—'
        ), false, $r['errors'] === [] ? INFO : ERROR);
        foreach ($r['errors'] as $e) {
            Session::addMessageAfterRedirect(htmlescape($e), false, ERROR);
        }
    }
}
Html::back();
