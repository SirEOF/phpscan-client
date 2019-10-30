<?php

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use \Symfony\Component\Console\Input\InputOption;

class ScanRunCommand extends Command
{

    protected static $defaultName = 'scan:run';

    public function __construct($name = null)
    {
        parent::__construct($name);
    }

    protected function configure()
    {
        $this
            ->setDescription('Scans PHP files for malwares in a given directory')
            ->addOption('apikey', 'k', InputOption::VALUE_REQUIRED, 'Purchased API key from phpscan.io')
            ->addOption('dir', 'd', InputOption::VALUE_REQUIRED, 'Absolute Base directory to scan PHP files inside it')
        ;
    }


    protected function execute(\Symfony\Component\Console\Input\InputInterface $input, \Symfony\Component\Console\Output\OutputInterface $output)
    {
        $helper = $this->getHelper('question');
        $io = new \Symfony\Component\Console\Style\SymfonyStyle($input, $output);

        $outputStyle = new \Symfony\Component\Console\Formatter\OutputFormatterStyle('blue', null);
        $output->getFormatter()->setStyle('help', $outputStyle);
        $io->writeln(['<help>For help, Pass --help to see options.</>', '']);

        $apiKey = $input->getOption('apikey');
        $baseDirectory = $input->getOption('dir');

        if (substr($baseDirectory, -1) !== '/') $baseDirectory .= '/';


    }


}