<?php

require_once __DIR__ .DIRECTORY_SEPARATOR .
                ".." . DIRECTORY_SEPARATOR .
                "app". DIRECTORY_SEPARATOR .
                "controllers". DIRECTORY_SEPARATOR .
                "ClientAgent.php";

require_once __DIR__ .DIRECTORY_SEPARATOR .
    ".." . DIRECTORY_SEPARATOR .
    "app". DIRECTORY_SEPARATOR .
    "commands". DIRECTORY_SEPARATOR .
    "ScanRunCommand.php";

use App\Controllers\ClientAgent;
use Symfony\Component\Console\Application;

$debug = false;
$application = new Application();
$clientAgent = new ClientAgent();

//$command = new \Symfony\Component\Console\Command\Command('scan:run');
//$command->setDescription('Scan all PHP files in a given directory');
//$command->addArgument();
$application->add(new ScanRunCommand());

return $application;
