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

namespace Wontonee\VerifiedSMS\Http\VerifiedSmsHashingLibrary;

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Wontonee\VerifiedSMS\Http\VerifiedSmsHashingLibrary\StringSanitizer;
use Mdanter\Ecc\Util\NumberSize;


mb_internal_encoding('UTF-8');

class HashCodeGenerator {
	private $stringSanitizer;

	private $adapter;
	private $generator;
  private $pemPub;

	private const HASH_CODE_LENGTH = 32;
	private const HASHING_ALGORITHM = 'sha256';
  private const RATE_LIMIT_TOKEN_SALT = 'xELpwbCabRriJEkOYBagfJpHrrmNqlaZMTxsacBQjsLjUHtQexWNQCiMCkrxBzWEifExJkkOJwOziTQQJyRWVUbauuCHZrYlenSAiqtKtT';

	public function __construct() {
		  $this->stringSanitizer = new StringSanitizer();

		  $this->adapter = EccFactory::getAdapter();
		  $this->generator = EccFactory::getNistCurves()->generator384();

      $derPub = new DerPublicKeySerializer();
      $this->pemPub = new PemPublicKeySerializer($derPub);
	}

	/**
     * Creates hash codes for the given key pair and message.
     *
     * @param $privateKey Private key of the brand.
     * @param $publicKeyAsString Public key of the brand as a base64 string.
     * @param $message The SMS message.
     * @return List of hash codes for the given parameters.
     */
    public function createHashes($privateKey, $publicKeyAsString, $message) {
        $publicKey = $this->pemPub->parse($publicKeyAsString);

        $exchange = $privateKey->createExchange($publicKey);
		    $sharedSecret = $exchange->calculateSharedKey();

        $binaryOfSharedKey = $this->adapter->intToFixedSizeString(
            $sharedSecret,
            NumberSize::bnNumBytes($this->adapter, $this->generator->getOrder())
        );

        return $this->getDigests($binaryOfSharedKey, $message);
    }

    /**
     * Creates a hash of the RATE_LIMIT_TOKEN_SALT based on a shared secret
     * computed from the given key pair.
     *
     * @param $privateKey Private key of the brand.
     * @param $publicKeyAsString Public key of the brand as a base64 string.
     * @return The unique hashcode for the rate limit token.
     */
    public function createRateLimitToken($privateKey, $publicKeyAsString) {
        $publicKey = $this->pemPub->parse($publicKeyAsString);

        $exchange = $privateKey->createExchange($publicKey);
		    $sharedSecret = $exchange->calculateSharedKey();

        $binaryOfSharedKey = $this->adapter->intToFixedSizeString(
            $sharedSecret,
            NumberSize::bnNumBytes($this->adapter, $this->generator->getOrder())
        );

        return $this->hkdfForHmacSha256($binaryOfSharedKey, self::RATE_LIMIT_TOKEN_SALT);
    }

    /**
     * Returns a list of SMS hash codes for the given argument and SMS message.
     *
     * @param $sharedKey The shared secret in binary between the brand's private key
     * and device's public key.
     * @param $message The SMS message.
     * @return List of SMS hash codes for the given arguments.
     */
    public function getDigests($sharedKey, $message) {
        $santizedMessage = $this->stringSanitizer->sanitize($message);

        $results = [];
        if ($santizedMessage != $message) {
            $results[] = $this->hkdfForHmacSha256($sharedKey, $santizedMessage);
        }

        $results[] = $this->hkdfForHmacSha256($sharedKey, $message);

        return $results;
    }

    /**
     * Calculates hash code by using HKDF and HMAC-SHA-2-256 algorithm using shared secret as the
     * input keying material and message bytes as application specific information.
     *
     * @param $sharedKey The shared secret between the brand's private key
     * and device's public key.
     * @param $message The SMS message.
     * @return The unique hashcode for the message.
     */
    function hkdfForHmacSha256($sharedKey, $message) {
		    $hash = hash_hkdf(self::HASHING_ALGORITHM, $sharedKey, self::HASH_CODE_LENGTH, $message);

		    return strtr(base64_encode($hash), '+/', '-_');
    }
}
