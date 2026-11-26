<?php

namespace GlpiPlugin\Vulnwatch\Compat;

/**
 * Base des objets de configuration (flux, versions cibles) soumis au droit « plugin_vulnwatch_config ».
 * GLPI 11 : $rightname non typé, comme dans la classe mère.
 */
abstract class ConfigRightDbtm extends \CommonDBTM
{
    public static $rightname = 'plugin_vulnwatch_config';

    public function __construct()
    {
        parent::__construct();
        $this->dohistory = true; // propriété typée en GLPI 12 : affectée ici plutôt que redéclarée
    }
}
