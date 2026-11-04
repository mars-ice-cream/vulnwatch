<?php

namespace GlpiPlugin\Vulnwatch\Console;

use Glpi\Console\AbstractCommand;
use GlpiPlugin\Vulnwatch\Cron;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** php bin/console plugins:vulnwatch:run --step=collect|analyze|tickets|all */
final class RunCommand extends AbstractCommand
{
    protected function configure()
    {
        parent::configure();
        $this->setName('plugins:vulnwatch:run');
        $this->setDescription('VulnWatch : exécute la collecte, l\'analyse et/ou les tickets automatiques');
        $this->addOption('step', 's', InputOption::VALUE_REQUIRED, 'collect, analyze, tickets ou all', 'all');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $step = (string) $input->getOption('step');
        if (in_array($step, ['collect', 'all'], true)) {
            $output->writeln('Collecte…');
            Cron::cronVulnwatchCollect();
        }
        if (in_array($step, ['analyze', 'all'], true)) {
            $output->writeln('Analyse…');
            $output->writeln(json_encode((new \GlpiPlugin\Vulnwatch\Matching\Analyzer())->run()));
        }
        if (in_array($step, ['tickets', 'all'], true)) {
            $output->writeln('Tickets automatiques…');
            $output->writeln(json_encode(\GlpiPlugin\Vulnwatch\Campaign::runAutomatic()));
        }
        return 0;
    }
}
