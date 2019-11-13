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

$application->add(new ScanRunCommand());

return $application;
