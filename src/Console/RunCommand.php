<?php

namespace GlpiPlugin\Vulnwatch\Console;

use Glpi\Console\AbstractCommand;
use GlpiPlugin\Vulnwatch\Cron;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** php bin/console plugins:vulnwatch:run --step=collect|analyze|all */
final class RunCommand extends AbstractCommand
{
    protected function configure()
    {
        parent::configure();
        $this->setName('plugins:vulnwatch:run');
        $this->setDescription('VulnWatch : exécute la collecte et/ou l\'analyse');
        $this->addOption('step', 's', InputOption::VALUE_REQUIRED, 'collect, analyze ou all', 'all');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
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
        return 0;
    }
}
