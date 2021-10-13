<?php


namespace Wontonee\Verifiedsms\Http\Controllers;

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;

use Wontonee\Verifiedsms\Http\VerifiedSmsClientLibrary\VerifiedSmsServiceClient;


class VerifiedsmsController extends Controller
{
    // agent id
    public $agentId;

    // private key
    public $privateKeyPath;

    // service account 
    public $serviceAccountLocation;

    // api key
    public $apiKey;

    //sms message to register
    public $sms;

    // mobile no with country code
    public $mobileno;
     


    public function __construct($agentId, $privateKeyPath, $serviceAccountLocation, $apiKey, $sms, $mobileno)
    {
        $this->agentId = $agentId;
        $this->privateKeyPath = $privateKeyPath;
        $this->serviceAccountLocation = $serviceAccountLocation;
        $this->apiKey = $apiKey;
        $this->sms = $sms;
        $this->mobileno = $mobileno;
    }

    /**
     * 
     * Create Hash store
     */
    public function GoogleHashstore()
    {
        // echo('testing for the package verified SMS.');
        $agentId = $this->agentId;
        $privateKeyPath = $this->privateKeyPath;
        $serviceAccountLocation = $this->serviceAccountLocation;
        $apiKey = $this->apiKey;

        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator384();

        $derPub = new DerPublicKeySerializer();
        $pemPriv = new PemPrivateKeySerializer(new DerPrivateKeySerializer($adapter, $derPub));

        // Read the private key .pem file content and create private key object
        $privateKey = $pemPriv->parse(file_get_contents($privateKeyPath));

        // Create instance of client library
        if ($serviceAccountLocation) {
            $verifiedSmsClient = new VerifiedSmsServiceClient(
                ['service_account_as_json' => file_get_contents($serviceAccountLocation)]
            );
        } else {
            $verifiedSmsClient = new VerifiedSmsServiceClient(
                ['api_key' => $apiKey]
            );
        }

        // Creates an array of devices, text messages, and postback data.
        // The postback data can be any string value and is what your webhook
        // will receive if you are using the real-time verification APIs.
        $sms = $this->sms;

        // Phone number with countrycode
        $recipientAndMessages = array(
            array(
                'phoneNumber' => $this->mobileno, 'text' => $sms,
                'postbackData' => $this->mobileno, 'agentId' => $agentId
            )
        );

        $phoneNumbers = array();
        foreach ($recipientAndMessages as $message) {
            $phoneNumbers[] = $message['phoneNumber'];
        }

        $userToKeys = $verifiedSmsClient->getEnabledUserKeys($phoneNumbers);
        $response = $verifiedSmsClient->createHashes(
            $recipientAndMessages,
            $privateKey,
            $userToKeys
        );

        if ($response == null) {
            return "0";
        } elseif ($response->getStatusCode() == 200) {
            return "200";
            //$response->getBody();
        } else {
            return $response->getReasonPhrase();
        }
    }
}
