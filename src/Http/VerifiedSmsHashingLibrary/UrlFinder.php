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

include_once __DIR__ . '/UrlExtractor.php';

mb_internal_encoding('UTF-8');

/**
 * A utility to find URLs in a given string.
 */
class UrlFinder {
	// Regex to match against emails, these will be ignored for URL matches
	private $emailRegex = '/[^@]+@[^@]+\.[^@]+/i';

	// Supported schemas to match against
	private $schemaRegexs = ['/http:\/\//i', '/https:\/\//i', '/rtsp:\/\//i'];

	// String literals for the supported schemas
	private $schemas = ['http://', 'https://', 'rtsp://'];

	// Default schema to add to a string if no schema is present
	private $defaultSchema = 'http://';

	private $urlExtractor;

	public function __construct() {
		$this->urlExtractor = new UrlExtractor();
	}

	/**
     * Finds URLs within the source string and returns an
     * array of objects with the normalized URL, where it starts
     * within the source and the length.
     *
     * @param $source string to search URLs for.
     * @return Array of URLs and their ranges in the source string.
     */
	public function find($source) {
		// Match all URLs in the source string
		preg_match_all($this->urlExtractor->urlMatcher, $source, $matches, PREG_OFFSET_CAPTURE);

		$seen = array();
		$results = array();

		// print_r($matches);

		foreach($matches as $match) {
			for($i = 0; $i < count($match); $i++) {
				// Make sure there is a string and index match
				if(is_array($match[$i]) && count($match[$i]) == 2) {
					$url = $match[$i][0];
					$index = $match[$i][1];

					// Convert the matching index into an index accounting for multibyte characters 
					$index = mb_strlen(mb_strcut($source, 0, $index));

					// Make sure this url and index combination is unique and it is not an email address
					if(!isset($seen[$url.'-'.$index]) && !filter_var($url, FILTER_VALIDATE_EMAIL)) {
						$normalizedUrl = $this->normalizedUrl($url);

						$results[] = array(
							'url' => $normalizedUrl,
							'start' => $index,
							'end' => $index + mb_strlen($url)
						);

						// Mark that we have seen this value before
						$seen[$url.'-'.$index] = true;
					}
				}
			}
		}

		return $results;
	}

	/**
     * Makes a URL from a given string, prepending it with
     * default schema if needed. Schema is always in lower case.
     *
     * @param $url The url string to build.
     * @return The url string with proper schema.
     */
	private function normalizedUrl($url) {
		$hasPrefix = false;

		for($i = 0; $i < count($this->schemaRegexs); $i++) {
			$regex = $this->schemaRegexs[$i];
			$schema = $this->schemas[$i];

			if(preg_match($regex, $url)) {
				$hasPrefix = true;
				$url = $schema . substr($url, strlen($schema));

				break;
			}
		}

		if(mb_substr($url, -1) == '.') {
			$url = substr($url, 0, strlen($url) - 1);
		}

		if(!$hasPrefix) {
			return $this->defaultSchema . $url;
		}

		return $url;
	}
}

?>