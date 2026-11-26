<?php

namespace GlpiPlugin\Vulnwatch\Compat;

/**
 * Base des objets de configuration (flux, versions cibles) soumis au droit « plugin_vulnwatch_config ».
 * GLPI 12 : $rightname typé string, comme dans la classe mère (PHP exige une déclaration identique).
 */
abstract class ConfigRightDbtm extends \CommonDBTM
{
    public static string $rightname = 'plugin_vulnwatch_config';

    public function __construct()
    {
        parent::__construct();
        $this->dohistory = true; // propriété typée en GLPI 12 : affectée ici plutôt que redéclarée
    }
}
