<?php

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;
use Symfony\Component\Finder\Finder;
use PhpParser\ParserFactory;
use PhpParser\Node\Stmt;

class ScanRunCommand extends Command
{

    protected static $defaultName = 'scan:run';

    /** @var \Symfony\Component\Console\Style\SymfonyStyle */
    private $io;
    private $mainAppBaseURI;
    private $logFile;
    private $writeLog;
    private $logLevel;
    private $debug;

    public function __construct($name = null)
    {
        parent::__construct($name);
        Dotenv\Dotenv::create(__DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR)->load();

        if (isset($_ENV['ENV'])) {
            if ($_ENV['ENV'] === 'local') {
                $this->mainAppBaseURI = $_ENV['MAIN_APP_BASE_URI_LOCAL'];
            } else if ($_ENV['ENV'] === 'prod') {
                $this->mainAppBaseURI = $_ENV['MAIN_APP_BASE_URI_PROD'];
            }
        } else {
            $this->mainAppBaseURI = "https://phpscan.io";
        }

        $this->logFile = 'scan.log';
        $this->writeLog = true;
        $this->logLevel = 1;
        $this->debug = false;
        if (!file_exists($this->logFile))
            file_put_contents($this->logFile, "");

    }

    protected function configure()
    {
        $this
            ->setDescription('Scans PHP files for malwares in a given directory')
            ->addOption('apikey', 'k', InputOption::VALUE_REQUIRED, 'Purchased API key from phpscan.io')
            ->addOption('dir', 'd', InputOption::VALUE_REQUIRED, 'Absolute Base directory to scan PHP files inside it')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $io = new SymfonyStyle($input, $output);
        $this->io = new SymfonyStyle($input, $output);
        $outputStyle = new OutputFormatterStyle('blue', null);
        $output->getFormatter()->setStyle('help', $outputStyle);
        $io->writeln(['<help>For help, Pass --help to see options.</>', '']);
        $apiKey = $input->getOption('apikey');
        $baseDirectory = $input->getOption('dir');
        $this->log(['======================= Starting New Scan ===========================']);
        if (substr($baseDirectory, -1) !== DIRECTORY_SEPARATOR) $baseDirectory .= DIRECTORY_SEPARATOR;
        if (!ctype_alnum($apiKey)) {
            $io->error('apikey is wrong');
            $this->log(['apikey is wrong']);
            die;
        }

        $phpFiles = $this->gatherPhpFiles($baseDirectory);
        $manifest = $this->hashes($phpFiles);

        $io->writeln('Checking manifest with scan server (It might take a while)...');
        $this->log(['Checking manifest with scan server (It might take a while)...']);
        $result = $this->checkManifestWithServer($manifest, $apiKey);
        if (isset($result['error'])) {
            $io->error($result['error']);
            $this->log($result['error']);
            die;
        }

        if (!isset($result['covered'])) {
            $io->error('API call to front server failed');
            $this->log(['API call to front server failed with the following error:', $result]);
            return;
        }

        $manifestRecord = $result['manifestRecordId'];
        $s3key = null;
        $covered = $result['covered'];
        if (!$covered) {
            $s3Token = $result['s3_token'];
            $s3Bucket = $result['s3_bucket'];
            $s3Region = $result['s3_region'];

            $io->writeln('Compressing...');
            $this->log(['Compressing files']);
            $s3key = $zipFileName = $apiKey . '-' . time() . ".zip";
            $zipFileNamePath = "archive". DIRECTORY_SEPARATOR . $zipFileName;
            if (!$this->compress($phpFiles, $baseDirectory, $zipFileNamePath)) {
                $io->error('Compression failed due to available disk space or permission');
                return;
            }

            $io->writeln('Uploading necessary files for scan...');
            $this->log(["Uploading necessary files for scan: $zipFileNamePath, $zipFileName"]);
            $uploadResult = $this->uploadToS3($zipFileNamePath, $s3Bucket, $s3Region, $zipFileName, $s3Token);
            if (!$uploadResult) {
                $io->error('Upload failed');
                unlink($zipFileNamePath);
                return;
            }

            unlink($zipFileNamePath);
        }

        $io->writeln('Acknowledging with server...');
        $this->log(["Acknowledging with server"]);
        try {
            $ackResult = $this->sendAckToServer($apiKey, $s3key, $covered, $manifestRecord, $result['paths'], $result['hashes'], $result['news'], $result['fileIds']);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            die;
        }

        if (!isset($ackResult['jobId'])) {
            $io->error('Failed to send acknowledge to server.');
            return;

        }

        $io->success("Scan Status Uri: " . $ackResult['reportUri']);
        $this->log(["Scan status URI: {$ackResult['reportUri']}"]);
        $io->writeln("Checking Job status:");
        $delay = 5;
        $topCount = 20;
        for($i=0; $i<=$topCount; $i++) {
            $status = $this->getJobStatus($ackResult, $apiKey);
            if (filter_var($status, FILTER_VALIDATE_URL)) {
                $io->success("Checkout scan job report: $status");
                break;
            } else {
                $io->writeln($delay*$i."s: $status");
            }

            if ($i === $topCount) {
                $io->warning("Scan job report is not ready yet. Please check your report later in dashboard");
                $this->log(["Scan job report is not ready yet. Please check your report later in dashboard"]);
                break;
            }
            sleep($delay);
        }
    }

    private function checkManifestWithServer($manifest, $apiKey) {
        $manifest['manifest_key'] = sha1(str_shuffle('abcdefghigklmnopqrstwxyz1234567890'));

        try {
            $client = new \GuzzleHttp\Client([
                'base_uri' => $this->mainAppBaseURI,
                'verify' => false,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $apiKey
                ]
            ]);

            $uri = "/api/job/check-manifest";
            $response = $client->post($uri, [
                GuzzleHttp\RequestOptions::JSON => $manifest
            ], [
                'timeout' => 1800
            ]);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            return $this->returnAndLogGuzzleError($e->getResponse());
        }

        if ($response->getStatusCode() !== 200)
            return $this->returnAndLogGuzzleError($response);

        return json_decode($response->getBody(), true);

    }

    private function sendAckToServer($apiKey, $key, $covered, $manifestRecordId, $paths, $hashes, $news, $fileIds) {

        try {
            $client = new \GuzzleHttp\Client([
                'base_uri' => $this->mainAppBaseURI,
                'verify' => false,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $apiKey
                ]
            ]);

            $uri = "/api/job/uploaded";
            $response = $client->post($uri, [
                GuzzleHttp\RequestOptions::JSON => [
                    'covered' => $covered,
                    's3key' => $key,
                    'manifestRecordId' => $manifestRecordId,
                    'paths' => $paths,
                    'hashes' => $hashes,
                    'news' => $news,
                    'fileIds' => $fileIds,
                    'apiKey' => $apiKey,
                ]
            ], [
                'timeout' => 1800
            ]);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            return $this->returnAndLogGuzzleError($e->getResponse());
        }

        if ($response->getStatusCode() !== 200)
            return $this->returnAndLogGuzzleError($response);

        return json_decode($response->getBody(), true);

    }

    /**
     * @param $baseDirectory string
     * @return array
     */
    private function gatherPhpFiles($baseDirectory) {

        $allFilesWithPhpExtension = $this->getAllFilesWithPhpExtension($baseDirectory);
        $allRealPhpFilesWithSize = $this->getApplicableFiles($allFilesWithPhpExtension);
        return $allRealPhpFilesWithSize;
    }

    private function getAllFilesWithPhpExtension($basePath) {
        $finder = new Finder();
        $results = [];
        $finder->files()->ignoreDotFiles(true)->in($basePath);
        foreach ($finder as $file) {
            $results[] = $file->getRealPath();
        }
        return $results;
    }

    private function getApplicableFiles($files) {

        $parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP5);
        $result = [];
        foreach ($files as $filePath) {
            $size = filesize($filePath);
            if($this->is_php($filePath, $parser)) {
                $this->io->writeln($filePath);
                $result[] = [$filePath,  $size];
            }

        }
        return $result;

    }

    /**
     * @param $path
     * @param $parser \PhpParser\Parser
     * @return bool
     */
    private function is_php($path, $parser) {
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        if ($extension!="php" and $extension!="inc")
        {
            if (filesize($path)>1 * 1024 * 1024) {
                return false;
            }

            $content = file_get_contents($path);
            if (strpos($content, '<?')===false) {
                return false;
            }

            try {
                $ast = $parser->parse($content);
                $content = null;
                $is_php=false;
                foreach ($ast as $node)
                {
                    if (!$node instanceof Stmt\InlineHTML)
                    {
                        $is_php=true;
                        break;
                    }
                }
                $ast = null;
                $content = null;
                if (!$is_php) {
                    return false;
                }
                $is_php=null;
            }
            catch (\Exception $e) {
                return false;
            }
            $content = null;
            return true;


        } else {
            return true;
        }
    }

    private function hash($filePath) {
        $algorithms =  ["crc32", "md5", "sha1"];
        $hashes = [];
        foreach($algorithms as $algo) {
            $hashes[] = hash_file($algo, $filePath);
        }
        return implode("",$hashes);
    }

    private function hashes($files) {
        $hashes = [];
        $sizes = [];
        $paths = [];
        foreach($files as $key => $value) {
            if(is_array($value)) {
                $hash = $this->hash($value[0]);
                if(in_array($hash, $hashes))
                    continue;
                $hashes[] = $hash;
                $sizes[] = ((int)$value[1])/(1024.0*1024.0);
                $paths[] = $value[0];
            }
        }
        return [
            'hashes'    => $hashes,
            'sizes'     => $sizes,
            'paths'     => $paths
        ];
    }

    /**
     * @param $path
     * @param $bucket
     * @param $region
     * @param $key
     * @param $s3PreSignedCredentials
     * @return bool
     */
    private function uploadToS3($path, $bucket, $region, $key, $s3PreSignedCredentials) {
        $client = new \GuzzleHttp\Client([
            'headers' => [
                "Accept" => "*/*",
                "Cache-Control" => "no-cache",
                "Content-Type" => "multipart/form-data;",
            ]
        ]);

        try {
            $response = $client->post($s3PreSignedCredentials[0]['action'], [
                'multipart' => [
                    [
                        'name' => 'acl',
                        'contents' => $s3PreSignedCredentials[1]['acl']
                    ],
                    [
                        'name' => 'key',
                        'contents' => $key
                    ],
                    [
                        'name' => 'X-Amz-Credential',
                        'contents' => $s3PreSignedCredentials[1]['X-Amz-Credential']
                    ],
                    [
                        'name' => 'X-Amz-Algorithm',
                        'contents' => $s3PreSignedCredentials[1]['X-Amz-Algorithm']
                    ],
                    [
                        'name' => 'X-Amz-Date',
                        'contents' => $s3PreSignedCredentials[1]['X-Amz-Date']
                    ],
                    [
                        'name' => 'Policy',
                        'contents' => $s3PreSignedCredentials[1]['Policy']
                    ],
                    [
                        'name' => 'X-Amz-Signature',
                        'contents' => $s3PreSignedCredentials[1]['X-Amz-Signature']
                    ],
                    [
                        'name' => 'file',
                        'contents' => file_get_contents($path)
                    ],
                ]
            ], [
                'timeout' => 1800
            ]);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            $this->returnAndLogGuzzleError($e->getResponse());
        }

        if ($response->getStatusCode() === 204) {
            return true;
        }

        $this->returnAndLogGuzzleError($response);
        return false;
    }



    /**
     * @param $files
     * @param $directory
     * @param $fileName
     * @return bool
     */
    private function compress($files, $directory, $fileName) {
        $zippy = \Alchemy\Zippy\Zippy::load();
        $params = [];
        $relativePaths = [];
        foreach($files as $file) {
            $relativePaths[] = str_replace($directory . DIRECTORY_SEPARATOR, "", $file[0]);
            $params[] = $file[0];
        }

        try {
            $archive = $zippy->create($fileName, $params);
            return true;
        } catch (\Alchemy\Zippy\Exception\RuntimeException $e) {
            switch ($this->logLevel) {
                case 1:
                    $this->log([$e->getMessage()]);
                    break;
                case 2:
                    $this->log($e->getTrace());
                    break;
            }
            return false;
        }

    }


    private function getJobStatus($serverAck, $apiKey) {

        $client = new \GuzzleHttp\Client([
            'headers' => [
                'Content-Type'  => 'application/x-www-form-urlencoded',
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer '.$apiKey
            ]
        ]);

        try {
            $response = $client->post($serverAck['reportUri'], [
                'timeout' => 1800
            ]);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            $this->returnAndLogGuzzleError($e->getResponse());
            return false;
        }

        if ($response->getStatusCode() !== 200) {
            $this->returnAndLogGuzzleError($response);
            return false;
        }

        return json_decode($response->getBody(), true);

    }

    /**
     * @param array $params
     */
    private function log($params) {
        if ($this->writeLog) {
            foreach ($params as $var)
                $this->internal_log($var);
        }
    }

    /**
     * @param mixed $var
     */
    private function internal_log($var) {
        if(!is_string($var))
            $var = var_export($var, true);
        elseif(is_object($var))
            $var = get_class($var);
        $str = "(" .
            date('m/d/Y h:i:s a')
            . "): " .
            trim($var) . PHP_EOL;
        $fp = fopen($this->logFile, 'a');
        fwrite($fp, $str);
        fclose($fp);
    }

    private function returnAndLogGuzzleError($response) {
        switch ($this->logLevel) {
            case 1:
                return "Request failed with statusCode={$response->getStatusCode()}";
                break;
            case 2:
                return $response->getBody()->getContents();
                break;
        }
    }

}