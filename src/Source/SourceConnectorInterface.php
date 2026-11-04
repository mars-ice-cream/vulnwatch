<?php

namespace GlpiPlugin\Vulnwatch\Source;

/**
 * Chaque source est un connecteur indépendant : il peut être activé, échouer ou
 * être remplacé sans affecter les autres. Les connecteurs ne reçoivent jamais
 * l'inventaire : le rapprochement est fait localement par Matching\Analyzer.
 */
interface SourceConnectorInterface
{
    public function getKey(): string;

    public function getLabel(): string;

    public function isEnabled(): bool;

    /** Description précise des données transmises à l'extérieur (affichée dans la configuration). */
    public function describeOutboundData(): string;

    /**
     * Exécute une passe de synchronisation, limitée à $budget unités de travail.
     * @return array{ok:bool, done:int, errors:int, message:string}
     */
    public function run(int $budget): array;
}
