<?php

namespace GlpiPlugin\Vulnwatch\Compat;

/**
 * Base des classes non persistées soumises au droit « plugin_vulnwatch ».
 * GLPI 12 : $rightname typé string, comme dans la classe mère (PHP exige une déclaration identique).
 */
abstract class PluginRightItem extends \CommonGLPI
{
    public static string $rightname = 'plugin_vulnwatch';
}
