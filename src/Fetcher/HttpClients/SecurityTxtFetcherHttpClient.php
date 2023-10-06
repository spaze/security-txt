<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\HttpClients;

use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;

interface SecurityTxtFetcherHttpClient
{

	/**
	 * @param list<string> $redirects
	 */
	public function getResponse(string $url, ?string $contextHost, array $redirects): SecurityTxtFetcherResponse;

}
