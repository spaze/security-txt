<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostnameException;

class SecurityTxtUrlParser
{

	/**
	 * @throws SecurityTxtHostnameException
	 */
	public function getHostFromUrl(string $url): string
	{
		// $url = https://example.com or https://example.com/foo
		$components = parse_url($url);
		if ($components && isset($components['host'])) {
			return $components['host'];
		}

		// $url = https:/example.com or https:/example.com/foo
		if ($components && isset($components['scheme'], $components['path']) && !isset($components['host'])) {
			$host = parse_url("{$components['scheme']}:/{$components['path']}", PHP_URL_HOST);
			if ($host) {
				return $host;
			}
		}

		// $url = example.com or example.com/foo
		$components = parse_url("//$url", PHP_URL_HOST);
		if ($components) {
			return $components;
		}

		throw new SecurityTxtHostnameException($url);
	}

}
