<?php
/*
Copyright 2019 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
namespace Wontonee\Verifiedsms\Http\VerifiedSmsClientLibrary;

use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Wontonee\Verifiedsms\Http\VerifiedSmsHashingLibrary\HashCodeGenerator;
use App\VerifiedSmsHashingLibrary\StringSanitizer;
use App\VerifiedSmsHashingLibrary\UrlExtractor;
use App\VerifiedSmsHashingLibrary\UrlFinder;
use Google_Client;
use FFI\Exception;



mb_internal_encoding('UTF-8');

class VerifiedSmsServiceClient {
    private const API_ROOT_URL = 'https://verifiedsms.googleapis.com/v1/';

    // Maximum number of times to retry refreshing an auth token
    private const MAX_AUTH_RETRIES = 2;

    private const HTTP_GET = 'GET';
    private const HTTP_PATCH = 'PATCH';
    private const HTTP_POST = 'POST';

    private $hashCodeGenerator;

    private $googleClient;

    private $serviceAccountAsJson;

    private $apiKey;

    private $httpClient;

    public function __construct($params) {
        $this->hashCodeGenerator = new HashCodeGenerator();
        $this->googleClient = new Google_Client();

        if (isset($params['service_account_as_json'])) {
            $this->serviceAccountAsJson = $params['service_account_as_json'];
        }
        else if (isset($params['api_key'])) {
            $this->apiKey = $params['api_key'];
        }
        else {
            throw new Exception('You must supply an API Key or Service Account details in the params associative array.');
        }

        $this->initHttpClient();
    }

    /**
     * Gets the phone number publics keys associated with each device.
     *
     * @param $phoneNumbers List of phone numbers.
     * @return Object representing device and public key pairs of enabled vsms users.
     */
    public function getEnabledUserKeys($phoneNumbers) {
        $jsonBody = json_encode(array('phoneNumbers' => $phoneNumbers));

        $response = $this->executeApiCall(self::API_ROOT_URL . 'enabledUserKeys:batchGet',
            $jsonBody, self::HTTP_POST);
        return $this->fetchUserKeys($response);
    }

    /**
     * Gets the public hashses associated with the recipients, uses these in combination with
     * the agent's private key to calculate message hash values, and then stores those
     * hash codes with Verified SMS.
     *
     * @param $recipientAndMessages An array of phone numbers and messages.
     * @param $privateKey A base64 string for the agent's private key.
     * @return The return object from Verified SMS.
     */
    public function createHashes($recipientAndMessages, $privateKey, $userToKeys = null) {
        $phoneNumbers = array();
        foreach($recipientAndMessages as $message) {
            $phoneNumbers[] = $message['phoneNumber'];
        }

        if ($userToKeys === null) {
            $userToKeys = $this->getEnabledUserKeys($phoneNumbers);
        }

        $hashedMessages = $this->calculateHashes($recipientAndMessages, $privateKey, $userToKeys);

        if (empty($hashedMessages)) {
            echo 'No hashes will be stored. Users are not VSMS-enabled.'.PHP_EOL;
            return;
        }

        $jsonBody = json_encode(array('messages' => $hashedMessages));

        print_r($jsonBody);

        return $this->executeApiCall(self::API_ROOT_URL . 'messages:batchCreate',
                                     $jsonBody, self::HTTP_POST);
    }

    /**
     * Updates the agent's registered public key.
     *
     * @param $agentId The unique agent id.
     * @param $publicKey The new public key to store for this agent.
     * @return The return object from Verified SMS.
     */
    public function updateKey($agentId, $publicKey) {
        $jsonBody = json_encode(array('publicKey' => $publicKey), JSON_FORCE_OBJECT);
        $urlPart = 'agents/' . $agentId . '/key';

        // Update the agent's public key with Verified SMS
        return $this->executeApiCall(self::API_ROOT_URL . $urlPart,
            $jsonBody, self::HTTP_PATCH);
    }

    /**
     * Get the agent's latest registered public key.
     *
     * @param $agentId The unique agent id.
     * @return The public key for the given agent from Verified SMS.
     */
    public function getAgentPublicKey($agentId) {
        $urlPart = 'agents/' . $agentId . '/key';

        // Update the agent's public key with Verified SMS
        $response = $this->executeApiCall(self::API_ROOT_URL . $urlPart, false, self::HTTP_GET);

        if ($response->getStatusCode() == 200) {
            $responseObject = json_decode($response->getBody());

            if (isset($responseObject->{'publicKey'})) {
                return $responseObject->{'publicKey'};
            }

            return '';
        }

        throw new Exception($response->getStatusCode() . ' - ' . $response->getReasonPhrase());
    }

    private function getPublicKeyFromPrivateKey($privateKey) {
        $derPub = new DerPublicKeySerializer();

        return base64_encode($derPub->serialize($privateKey->getPublicKey()));
    }

    /**
     * Iterates over the phone number to message pairs and calculates hash codes
     * for each combination.
     *
     * @param $recipientAndMessages A Map of phone number to message mappings.
     * @param $privateKey A base64 string for the agent's private key.
     * @param $userToKeys Mapping of phone number to public key pairs.
     * @return The return object from Verified SMS.
     */
    private function calculateHashes($recipientAndMessages, $privateKey, $userToKeys) {
        $messages = array();

        foreach ($recipientAndMessages as $message) {
            if(!array_key_exists($message['phoneNumber'], $userToKeys)) {
                continue;
            }
            $publicDeviceKey = $userToKeys[$message['phoneNumber']];

            // Compute hash code for this private/public key combination and message
            $hashCodes = $this->hashCodeGenerator->createHashes($privateKey,
                $publicDeviceKey, $message['text']);

            $rateLimitToken = $this->hashCodeGenerator->createRateLimitToken($privateKey,
                    $publicDeviceKey);

            $postbackData = base64_encode($message['postbackData']);
            $agentId = $message['agentId'];

            // Add the hash of the rate limit token for each sanitized hash
            foreach($hashCodes as $hashCode) {
                $messages[] = array('hash' => $hashCode,
                                    'rateLimitToken' => $rateLimitToken,
                                    'postbackData' => $postbackData,
                                    'agentId' => $agentId
                                   );
            }
        }

        return $messages;
    }

    /**
     * Executes the API call with Verified SMS.
     *
     * @param $apiEndpointUrl The API endpoint to call.
     * @param $jsonBody The JSON body to POST to the endpoint.
     * @param $method The HTTP method to use (e.g. POST, PATCH).
     * @return The JSON returned by the API call.
     */
    private function executeApiCall($apiEndpointUrl, $jsonBody, $method) {
        if ($method === 'GET') {
            $response = $this->httpClient->request('GET', $apiEndpointUrl);
        }
        else {
            $response = $this->httpClient->request($method, $apiEndpointUrl, [
                'body' => $jsonBody
            ]);
        }

        return $response;
    }

    private function initHttpClient() {
        if ($this->apiKey) {
            $this->googleClient->setDeveloperKey($this->apiKey);
        }
        else {
            $authObject = json_decode($this->serviceAccountAsJson);

            // Initializes the Google client with the Verifies SMS api scope
            $this->googleClient->addScope('https://www.googleapis.com/auth/verifiedsms');

            // application default credentials
            $this->googleClient->useApplicationDefaultCredentials();

            // set the information from the config
            $this->googleClient->setClientId($authObject->{'client_id'});
            $this->googleClient->setConfig('client_email', $authObject->{'client_email'});
            $this->googleClient->setConfig('signing_key', $authObject->{'private_key'});
            $this->googleClient->setConfig('signing_algorithm', 'HS256');
        }

        // returns a Guzzle HTTP Client
        $this->httpClient = $this->googleClient->authorize();
    }

    private function fetchUserKeys($response) {
        if ($response->getStatusCode() != 200) {
            throw new Exception($response->getStatusCode() . ' - ' . $response->getReasonPhrase());
        }
        $responseObject = json_decode($response->getBody());
        $userToKeys = array();
        if (isset($responseObject->{'userKeys'})) {
            for($i = 0; $i < count($responseObject->{'userKeys'}); $i++) {
                $value = $responseObject->{'userKeys'}[$i];
                $userToKeys[$value->{'phoneNumber'}] = $value->{'publicKey'};
            }
        }
        return $userToKeys;
    }
}

?>
