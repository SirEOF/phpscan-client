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
use Aws\S3\S3Client;

class ScanRunCommand extends Command
{

    protected static $defaultName = 'scan:run';

    /** @var \Symfony\Component\Console\Style\SymfonyStyle */
    private $io;

    private $mainAppBaseURI;

    public function __construct($name = null)
    {
        parent::__construct($name);
        Dotenv\Dotenv::create(__DIR__ . "/../../")->load();

        if ($_ENV['ENV'] === 'local') {
            $this->mainAppBaseURI = $_ENV['MAIN_APP_BASE_URI_LOCAL'];
        } else if ($_ENV['ENV'] === 'prod') {
            $this->mainAppBaseURI = $_ENV['MAIN_APP_BASE_URI_PROD'];
        }

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

        if (substr($baseDirectory, -1) !== '/') $baseDirectory .= '/';
        if (!ctype_alnum($apiKey)) {
            $io->error('apikey is wrong');
            die;
        }

        $phpFiles = $this->gatherPhpFiles($baseDirectory);
        $manifest = $this->hashes($phpFiles);

        $io->writeln('Checking manifest with scan server');
        $result = $this->checkManifestWithServer($manifest, $apiKey);
        $manifestRecord = $result['manifestRecordId'];

        if (!isset($result['covered'])) {
            $io->error('API call to front server failed');
            return;
        }

        $s3key = null;
        $covered = $result['covered'];
        if (!$covered) {
            $s3Token = $result['s3_token'];
            $s3Bucket = $result['s3_bucket'];
            $s3Region = $result['s3_region'];

            $io->writeln('Compressing...');
            $s3key = $zipFileName = $apiKey . '-' . time() . ".zip";
            $zipFileNamePath = "archive/" . $zipFileName;
            if (!$this->compress($phpFiles, $baseDirectory, $zipFileNamePath)) {
                $io->error('Compression failed due to available disk space or permission');
                return;
            }

            $io->writeln('Uploading...');
            $uploadResult = $this->uploadToS3($zipFileNamePath, $s3Bucket, $s3Region, $zipFileName, $s3Token);
            if ($uploadResult['status'] !== 'done') {
                $io->error('Upload failed');
                unlink($zipFileNamePath);
                return;
            }

            unlink($zipFileNamePath);
        }

        $io->writeln('Acknowledging server...');
        $ackResult = $this->sendAckToServer($apiKey, $s3key, $covered, $manifestRecord, $manifest['paths'], $manifest['hashes'], $result['news'], $result['fileIds']);
        if (isset($ackResult['jobId'])) {
            $io->success($ackResult['reportUri']);
            return;
        } else {
            $io->error('Failed to send acknowledge to server.');
        }

    }

    private function checkManifestWithServer($manifest, $apiKey) {
        $manifest['manifest_key'] = sha1(str_shuffle('abcdefghigklmnopqrstwxyz1234567890'));

        $client = new \GuzzleHttp\Client([
            'base_uri' => $this->mainAppBaseURI,
            'verify' => false,
            'headers' => [
                'Content-Type'  => 'application/x-www-form-urlencoded',
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer '.$apiKey
            ]
        ]);

        $uri = "/api/job/check-manifest";
        $response = $client->post($uri, [
            GuzzleHttp\RequestOptions::JSON => $manifest
        ], [
            'timeout' => 600
        ]);
        return json_decode($response->getBody(), true);

    }

    private function sendAckToServer($apiKey, $key, $covered, $manifestRecordId, $paths, $hashes, $news, $fileIds) {

        $client = new \GuzzleHttp\Client([
            'base_uri' => $this->mainAppBaseURI,
            'verify' => false,
            'headers' => [
                'Content-Type'  => 'application/x-www-form-urlencoded',
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer '.$apiKey
            ]
        ]);

        $uri = "/api/job/uploaded";
        $response = $client->post($uri, [
            GuzzleHttp\RequestOptions::JSON => [
                's3key' => $key,
                'manifestRecordId' => $manifestRecordId,
                'paths' => $paths,
                'hashes' => $hashes,
                'news' => $news,
                'covered' => $covered,
                'fileIds' => $fileIds,
                'apiKey' => $apiKey,
            ]
        ], [
            'timeout' => 600
        ]);
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
        $finder->files()->in($basePath);
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
        $content = file_get_contents($path);
        if (strpos($content, '<?')===false) {
            return false;
        }
//        try {
//            $ast = $parser->parse($content);
//            $content = null;
//            $is_php=false;
//            foreach ($ast as $node)
//            {
//                if (!$node instanceof Stmt\InlineHTML)
//                {
//                    $is_php=true;
//                    break;
//                }
//            }
//            if (!$is_php) {
////                if(self::DEBUG)  dump("after loop and is_php is false");
//                return false;
//            }
//        }
//        catch (\Exception $e) {
////            if(self::DEBUG)  dump("at exception so is false");
//            return false;
//        }
//        if(self::DEBUG)  dump("at the end so is php is true");
        $content = null;
        return true;
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
            error_log(json_encode($value));
            if(is_array($value)) {
                $hash = $this->hash($value[0]);
                if(in_array($hash, $hashes))
                    continue;
                $hashes[] = $hash;
                $sizes[] = (int)$value[1]/(1024*1024);
                $paths[] = $value[0];
//                $result[$value[0]][0] = $hash;
//                $result[$value[0]][1] = $value[1];
            }
        }
        return [
            'hashes'    => $hashes,
            'sizes'     => $sizes,
            'paths'     => $paths
        ];
    }


    /**
     * @param string $path
     * @param string $bucket
     * @param string $region
     * @param string[80] $key
     * @param array $s3PreSignedCredentials
     * @return array
     */
    private function uploadToS3($path, $bucket, $region, $key, $s3PreSignedCredentials) {
        $s3Client = new S3Client([
            'region' => $region,
            'version' => 'latest'
        ]);
        $response = [];
        $bucketExistence = $s3Client->doesBucketExist($bucket);
        if ($bucketExistence && !$s3Client->doesObjectExist($bucket, $key)) {
            try {

                $params = array_merge($s3PreSignedCredentials, [
                    'Key'       => $key,
                    'Bucket'    => $bucket,
                    'Body'      => file_get_contents($path)
                ]);

                $result = $s3Client->putObject($params);
                $response['status'] = 'done';
            }
            catch (\Aws\Exception\AwsException $e) {
                $response['status'] = 'error';
                $response['message'] = 'could not upload object to bucket! '.$bucket
                    ." ".$key;
            }
        } else {
            if(!$bucketExistence) {
                $response['status'] = 'error';
                $response['message'] = 'bucket does not exist! '.$bucket
                    ." ".$key;
            }
            else {
                $response['status'] = 'ok';
                $response['message'] = 'key already existed in the bucket! '.$bucket
                    ." ".$key;
            }
        }
        return $response;
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
            $relativePaths[] = str_replace($directory."/", "", $file[0]);
            $params[] = $file[0];
        }

        try {
            $archive = $zippy->create($fileName, $params);
            return true;
        } catch (\Alchemy\Zippy\Exception\RuntimeException $e) {
            return false;
        }

    }

}