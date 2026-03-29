<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\HttpClients;

use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherUrl;

interface SecurityTxtFetcherHttpClient
{

	/**
	 * @phpstan-param DNS_A|DNS_AAAA $ipAddressType
	 * @psalm-param int $ipAddressType
	 */
	public function getResponse(SecurityTxtFetcherUrl $url, string $host, string $ipAddress, int $ipAddressType): SecurityTxtFetcherResponse;

}
