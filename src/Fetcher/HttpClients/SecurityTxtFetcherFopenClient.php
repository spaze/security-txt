<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\HttpClients;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotReadUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;

class SecurityTxtFetcherFopenClient implements SecurityTxtFetcherHttpClient
{

	/**
	 * @param list<string> $redirects
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtNoHttpCodeException
	 */
	public function getResponse(string $url, ?string $contextHost, array $redirects): SecurityTxtFetcherResponse
	{

		$options = [
			'http' => [
				'follow_location' => false,
				'ignore_errors' => true,
				'user_agent' => 'spaze/security-txt',
			],
		];
		if ($contextHost) {
			$options['ssl'] = [
				'peer_name' => $contextHost,
			];
			$options['http']['header'][] = "Host: {$contextHost}";
		}
		$fp = @fopen($url, 'r', context: stream_context_create($options)); // intentionally @, converted to exception
		if (!$fp) {
			throw new SecurityTxtCannotOpenUrlException($url, $redirects);
		}
		$contents = stream_get_contents($fp);
		if ($contents === false) {
			throw new SecurityTxtCannotReadUrlException($url, $redirects);
		}
		$metadata = stream_get_meta_data($fp);
		fclose($fp);
		/** @var list<string> $wrapperData */
		$wrapperData = $metadata['wrapper_data'];
		if (preg_match('~^HTTP/[\d.]+ (\d+)~', $wrapperData[0], $matches)) {
			$code = (int)$matches[1];
		} else {
			throw new SecurityTxtNoHttpCodeException($url, $redirects);
		}

		$headers = [];
		for ($i = 1; $i < count($wrapperData); $i++) {
			$parts = explode(':', $wrapperData[$i], 2);
			$headers[strtolower(trim($parts[0]))] = trim($parts[1]);
		}
		return new SecurityTxtFetcherResponse($code, $headers, $contents);
	}

}
