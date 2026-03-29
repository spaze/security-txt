<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\HttpClients;

use CurlHandle;
use Override;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherUrl;

final readonly class SecurityTxtFetcherCurlClient implements SecurityTxtFetcherHttpClient
{

	private const int MAX_RESPONSE_LENGTH = 10_000;
	private const string DEFAULT_USER_AGENT = 'Mozilla/5.0 (compatible; spaze/security-txt; +https://github.com/spaze/security-txt)';


	public function __construct(
		private string $userAgent = self::DEFAULT_USER_AGENT,
	) {
	}


	/**
	 * @phpstan-param DNS_A|DNS_AAAA $ipAddressType
	 * @psalm-param int $ipAddressType
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtConnectedToWrongIpAddressException
	 */
	#[Override]
	public function getResponse(SecurityTxtFetcherUrl $url, string $host, string $ipAddress, int $ipAddressType): SecurityTxtFetcherResponse
	{
		$ch = curl_init($url->getUrl());
		if ($ch === false) {
			throw new SecurityTxtCannotOpenUrlException($url->getUrl(), $url->getRedirects());
		}

		$rawHeaders = [];
		$contents = '';
		$truncated = false;
		$components = parse_url($url->getUrl());
		if ($components === false) {
			throw new SecurityTxtCannotOpenUrlException($url->getUrl(), $url->getRedirects());
		}
		$port = $components['port'] ?? (isset($components['scheme']) && strtolower($components['scheme']) === 'http' ? 80 : 443);
		curl_setopt_array($ch, [
			CURLOPT_RETURNTRANSFER => false,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_FAILONERROR => false,
			CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_TIMEOUT => 10,
			CURLOPT_LOW_SPEED_LIMIT => 10,
			CURLOPT_LOW_SPEED_TIME => 5,
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_SSL_VERIFYPEER => true,
			CURLOPT_ENCODING => '', // '' means that the Accept-Encoding: header containing all supported encoding types is sent
			CURLOPT_FORBID_REUSE => true,
			CURLOPT_FRESH_CONNECT => true,
			CURLOPT_HTTPHEADER => ["Host: {$host}"],
			CURLOPT_USERAGENT => $this->userAgent,
			CURLOPT_HEADER => false,
			CURLOPT_RESOLVE => [sprintf('%s:%s:%s', $host, $port, $ipAddressType === DNS_AAAA ? "[{$ipAddress}]" : $ipAddress)],
			CURLOPT_HEADERFUNCTION => function (CurlHandle $ch, string $header) use (&$rawHeaders): int {
				$rawHeaders[] = trim($header);
				return strlen($header);
			},
			CURLOPT_WRITEFUNCTION => function (CurlHandle $ch, string $data) use (&$contents, &$truncated): int {
				$length = strlen($data);
				$remaining = self::MAX_RESPONSE_LENGTH - strlen($contents);
				if ($remaining <= 0) {
					$truncated = true;
					return 0; // Stops transfer, but also throws a write error, which we'll have to discard
				}
				if ($length > $remaining) {
					$contents .= substr($data, 0, $remaining);
					$truncated = true;
					return $remaining;
				}
				$contents .= $data;
				return $length;
			},
		]);

		$result = curl_exec($ch);
		if ($result === false) {
			$error = curl_errno($ch);
			if ($error !== CURLE_WRITE_ERROR || !$truncated) {
				throw new SecurityTxtCannotOpenUrlException($url->getUrl(), $url->getRedirects());
			}
		}

		$primaryIp = curl_getinfo($ch, CURLINFO_PRIMARY_IP);
		$primaryIpBinary = inet_pton($primaryIp);
		$expectedIpBinary = inet_pton($ipAddress);
		if ($primaryIpBinary === false || $expectedIpBinary === false || $primaryIpBinary !== $expectedIpBinary) {
			throw new SecurityTxtConnectedToWrongIpAddressException($ipAddress, $primaryIp, $url->getUrl(), $url->getRedirects());
		}

		$code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
		if ($code === 0) {
			throw new SecurityTxtNoHttpCodeException($url->getUrl(), $url->getRedirects());
		}

		$headers = [];
		foreach ($rawHeaders as $i => $line) {
			if ($i === 0) {
				// status line, already handled via curl_getinfo
				continue;
			}
			if ($line === '') {
				continue;
			}
			$parts = explode(':', $line, 2);
			if (count($parts) === 2) {
				$headers[strtolower(trim($parts[0]))] = trim($parts[1]);
			}
		}

		return new SecurityTxtFetcherResponse(
			$code,
			$headers,
			$contents,
			$truncated,
			$ipAddress,
			$ipAddressType,
		);
	}

}
